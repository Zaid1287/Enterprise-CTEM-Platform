import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Plus, Trash2, Pencil, Wifi, WifiOff, Clock, RefreshCw,
  Loader2, TestTube2, Upload, Check, X, KeyRound, Eye, EyeOff,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import { Textarea } from "@/components/ui/textarea";
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
  id: number; ip: string; port: number; label: string | null; type: string;
  country: string | null; asn: string | null;
  username: string | null;
  hasAuth: boolean;
  healthScore: number; successCount: number; failCount: number;
  count429: number; count403: number; avgLatencyMs: number | null;
  status: "active" | "cooldown" | "inactive"; lastTestedAt: string | null;
  requestsToday?: number;
}

interface BulkResult {
  imported: number; failed: number; total: number;
  results: Array<{ ip: string; port: number; ok: boolean; latencyMs?: number; error?: string }>;
}

/* ─── API helpers ─────────────────────────────────────────────────────── */
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
  const s = map[status] ?? { label: status, icon: RefreshCw, cls: "bg-muted text-muted-foreground" };
  const Icon = s.icon;
  return (
    <Badge variant="outline" className={cn("text-xs font-medium gap-1", s.cls)}>
      <Icon className="w-3 h-3" />{s.label}
    </Badge>
  );
}

/* ─── Issue 2: Add / Edit Dialog with username/password ──────────────── */
function ProxyDialog({ open, onClose, initial }: { open: boolean; onClose: () => void; initial?: Proxy }) {
  const qc = useQueryClient();
  const { toast } = useToast();
  const [ip, setIp]           = useState(initial?.ip ?? "");
  const [port, setPort]       = useState(String(initial?.port ?? "3128"));
  const [label, setLabel]     = useState(initial?.label ?? "");
  const [type, setType]       = useState(initial?.type ?? "http");
  const [country, setCountry] = useState(initial?.country ?? "");
  const [asn, setAsn]         = useState(initial?.asn ?? "");
  const [username, setUsername] = useState(initial?.username ?? "");
  const [password, setPassword] = useState("");
  const [showPwd, setShowPwd]   = useState(false);

  const isEdit = !!initial;

  const saveMut = useMutation({
    mutationFn: (body: object) =>
      isEdit
        ? api(`/api/scan-proxies/${initial!.id}`, { method: "PATCH", body: JSON.stringify(body) })
        : api("/api/scan-proxies",                { method: "POST",  body: JSON.stringify(body) }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["scan-proxies"] });
      toast({ title: isEdit ? "Proxy updated" : "Proxy added" });
      onClose();
    },
    onError: (e: Error) => toast({ title: "Failed", description: e.message, variant: "destructive" }),
  });

  const handleSubmit = () => {
    if (!ip.trim()) { toast({ title: "IP required", variant: "destructive" }); return; }
    const body: Record<string, any> = {
      ip: ip.trim(), port: parseInt(port, 10), label: label || undefined,
      type, country: country || undefined, asn: asn || undefined,
      username: username || undefined,
    };
    // Only send password if it was changed (non-empty)
    if (password) body.password = password;
    saveMut.mutate(body);
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

          {/* Issue 2: Proxy auth credentials */}
          <div className="border-t pt-3">
            <div className="flex items-center gap-1.5 mb-3">
              <KeyRound className="w-3.5 h-3.5 text-muted-foreground" />
              <p className="text-xs font-medium text-muted-foreground">Authentication (optional)</p>
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <Label>Username</Label>
                <Input placeholder="user" value={username} onChange={e => setUsername(e.target.value)} autoComplete="off" />
              </div>
              <div className="space-y-1.5">
                <Label>{isEdit ? "New Password" : "Password"}</Label>
                <div className="relative">
                  <Input
                    type={showPwd ? "text" : "password"}
                    placeholder={isEdit ? "leave blank to keep" : "pass"}
                    value={password}
                    onChange={e => setPassword(e.target.value)}
                    autoComplete="new-password"
                    className="pr-8"
                  />
                  <button
                    type="button"
                    className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                    onClick={() => setShowPwd(v => !v)}
                  >
                    {showPwd ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                  </button>
                </div>
              </div>
            </div>
            {isEdit && initial?.hasAuth && !password && (
              <p className="text-xs text-muted-foreground mt-1.5">
                Credentials already set. Leave blank to keep the existing password.
              </p>
            )}
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

/* ─── Issue 3: Bulk Import Dialog ────────────────────────────────────── */
function BulkImportDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const qc = useQueryClient();
  const { toast } = useToast();
  const [text, setText] = useState("");
  const [result, setResult] = useState<BulkResult | null>(null);
  const [loading, setLoading] = useState(false);

  const handleImport = async () => {
    if (!text.trim()) { toast({ title: "Paste proxy list first", variant: "destructive" }); return; }
    setLoading(true);
    try {
      const res = await api<BulkResult>("/api/scan-proxies/bulk", {
        method: "POST",
        body: JSON.stringify({ proxies: text }),
      });
      setResult(res);
      qc.invalidateQueries({ queryKey: ["scan-proxies"] });
      toast({ title: `Imported ${res.imported} proxies`, description: `${res.failed} failed.` });
    } catch (e: any) {
      toast({ title: "Bulk import failed", description: e.message, variant: "destructive" });
    } finally {
      setLoading(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={v => { if (!v) { onClose(); setResult(null); setText(""); } }}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle>Bulk Import Proxies</DialogTitle>
        </DialogHeader>
        <div className="space-y-4 py-2">
          {!result ? (
            <>
              <p className="text-sm text-muted-foreground">
                Paste one proxy per line. Supported formats:
              </p>
              <div className="bg-muted/50 rounded-lg px-3 py-2 font-mono text-xs text-muted-foreground space-y-0.5">
                <div>ip:port</div>
                <div>ip:port:username:password</div>
                <div>ip:port:username:password:label</div>
              </div>
              <Textarea
                placeholder={"1.2.3.4:8080\n5.6.7.8:3128:user:secret\n9.10.11.12:8888:user:pass:Datacenter-US"}
                value={text}
                onChange={e => setText(e.target.value)}
                rows={10}
                className="font-mono text-xs"
              />
              <p className="text-xs text-muted-foreground">
                Each proxy will be health-checked (TCP ping) before import. This may take a moment.
              </p>
            </>
          ) : (
            <div className="space-y-3">
              <div className="grid grid-cols-3 gap-3 text-center">
                <div className="rounded-lg border bg-green-500/10 p-3">
                  <p className="text-2xl font-bold text-green-600">{result.imported}</p>
                  <p className="text-xs text-muted-foreground mt-0.5">Imported</p>
                </div>
                <div className="rounded-lg border bg-red-500/10 p-3">
                  <p className="text-2xl font-bold text-red-500">{result.failed}</p>
                  <p className="text-xs text-muted-foreground mt-0.5">Failed</p>
                </div>
                <div className="rounded-lg border bg-muted p-3">
                  <p className="text-2xl font-bold">{result.total}</p>
                  <p className="text-xs text-muted-foreground mt-0.5">Total</p>
                </div>
              </div>
              <div className="max-h-48 overflow-y-auto space-y-1">
                {result.results.map((r, i) => (
                  <div key={i} className={cn("flex items-center gap-2 text-xs px-2 py-1 rounded", r.ok ? "bg-green-500/5" : "bg-red-500/5")}>
                    {r.ok
                      ? <Check className="w-3 h-3 text-green-600 shrink-0" />
                      : <X className="w-3 h-3 text-red-500 shrink-0" />
                    }
                    <span className="font-mono">{r.ip}:{r.port}</span>
                    {r.ok && r.latencyMs != null && <span className="text-muted-foreground ml-auto">{r.latencyMs}ms</span>}
                    {!r.ok && r.error && <span className="text-red-500 ml-auto truncate max-w-32" title={r.error}>{r.error}</span>}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
        <DialogFooter>
          {!result ? (
            <>
              <Button variant="ghost" onClick={onClose} disabled={loading}>Cancel</Button>
              <Button onClick={handleImport} disabled={loading || !text.trim()}>
                {loading && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
                Import & Test
              </Button>
            </>
          ) : (
            <Button onClick={() => { onClose(); setResult(null); setText(""); }}>Done</Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

/* ─── Issue 9: Inline Editable Row ──────────────────────────────────── */
interface InlineEdit {
  ip: string; port: string; label: string; type: string;
  country: string; asn: string; username: string; password: string;
}

function InlineProxyRow({
  proxy, isSuperAdmin, testingId, onTest, onDelete,
  onCancelEdit,
}: {
  proxy: Proxy;
  isSuperAdmin: boolean;
  testingId: number | null;
  onTest: (p: Proxy) => void;
  onDelete: (p: Proxy) => void;
  onCancelEdit: () => void;
}) {
  const qc = useQueryClient();
  const { toast } = useToast();
  const [row, setRow] = useState<InlineEdit>({
    ip: proxy.ip, port: String(proxy.port),
    label: proxy.label ?? "", type: proxy.type,
    country: proxy.country ?? "", asn: proxy.asn ?? "",
    username: proxy.username ?? "", password: "",
  });
  const [saving, setSaving] = useState(false);

  const save = async () => {
    if (!row.ip.trim()) { toast({ title: "IP required", variant: "destructive" }); return; }
    setSaving(true);
    try {
      const body: Record<string, any> = {
        ip: row.ip.trim(), port: parseInt(row.port, 10),
        label: row.label || null, type: row.type,
        country: row.country || null, asn: row.asn || null,
        username: row.username || null,
      };
      if (row.password) body.password = row.password;
      await api(`/api/scan-proxies/${proxy.id}`, { method: "PATCH", body: JSON.stringify(body) });
      qc.invalidateQueries({ queryKey: ["scan-proxies"] });
      toast({ title: "Proxy updated" });
      onCancelEdit();
    } catch (e: any) {
      toast({ title: "Update failed", description: e.message, variant: "destructive" });
    } finally {
      setSaving(false);
    }
  };

  const cell = "px-2 py-1.5";
  const inp = "h-7 text-xs px-2";

  return (
    <tr className="border-b bg-blue-500/5">
      <td className={cell}><Input className={inp} value={row.ip} onChange={e => setRow(r => ({ ...r, ip: e.target.value }))} placeholder="1.2.3.4" /></td>
      <td className={cell}><Input className={inp} value={row.label} onChange={e => setRow(r => ({ ...r, label: e.target.value }))} placeholder="Label" /></td>
      <td className={cell}>
        <Select value={row.type} onValueChange={v => setRow(r => ({ ...r, type: v }))}>
          <SelectTrigger className={inp}><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem value="datacenter">Datacenter</SelectItem>
            <SelectItem value="residential">Residential</SelectItem>
            <SelectItem value="isp">ISP</SelectItem>
            <SelectItem value="mobile">Mobile</SelectItem>
            <SelectItem value="socks5">SOCKS5</SelectItem>
            <SelectItem value="http">HTTP</SelectItem>
          </SelectContent>
        </Select>
      </td>
      <td className={cell}><Input className={inp} value={row.country} onChange={e => setRow(r => ({ ...r, country: e.target.value }))} placeholder="DE" maxLength={3} /></td>
      <td className={cell}><Input className={inp} value={row.asn} onChange={e => setRow(r => ({ ...r, asn: e.target.value }))} placeholder="ASN" /></td>
      {/* Health / successPct / 429s / 403s / latency — read-only in inline edit */}
      <td className="px-2 py-1.5 text-right text-xs font-bold" style={{ color: proxy.healthScore >= 70 ? "#16a34a" : proxy.healthScore >= 30 ? "#f59e0b" : "#ef4444" }}>{proxy.healthScore}</td>
      <td className="px-2 py-1.5 text-right text-xs text-muted-foreground">—</td>
      <td className="px-2 py-1.5 text-right text-xs">{proxy.count429}</td>
      <td className="px-2 py-1.5 text-right text-xs">{proxy.count403}</td>
      <td className="px-2 py-1.5 text-right text-xs text-muted-foreground">{proxy.avgLatencyMs != null ? `${proxy.avgLatencyMs}ms` : "—"}</td>
      <td className={cell} colSpan={2}>
        {/* Auth credentials inline */}
        <div className="flex gap-1.5">
          <Input className={inp} value={row.username} onChange={e => setRow(r => ({ ...r, username: e.target.value }))} placeholder="user (opt)" />
          <Input className={inp} type="password" value={row.password} onChange={e => setRow(r => ({ ...r, password: e.target.value }))} placeholder="pass (opt)" />
        </div>
      </td>
      <td className={cell}>
        <div className="flex items-center gap-1">
          <Button variant="ghost" size="icon" className="w-7 h-7 text-green-600 hover:text-green-700" title="Save" onClick={save} disabled={saving}>
            {saving ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Check className="w-3.5 h-3.5" />}
          </Button>
          <Button variant="ghost" size="icon" className="w-7 h-7 text-muted-foreground" title="Cancel" onClick={onCancelEdit} disabled={saving}>
            <X className="w-3.5 h-3.5" />
          </Button>
        </div>
      </td>
    </tr>
  );
}

/* ─── Main Page ───────────────────────────────────────────────────────── */
export default function ScanProxiesPage() {
  const { user } = useAuth();
  const isSuperAdmin = user?.role === "super_admin";
  const { toast } = useToast();
  const qc = useQueryClient();
  const [showAdd, setShowAdd]     = useState(false);
  const [showBulk, setShowBulk]   = useState(false);
  const [editingId, setEditingId] = useState<number | null>(null); // Issue 9: inline edit
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
          <div className="flex gap-2">
            {/* Issue 3: Bulk import button */}
            <Button variant="outline" onClick={() => setShowBulk(true)} className="gap-1.5">
              <Upload className="w-4 h-4" /> Bulk Import
            </Button>
            <Button onClick={() => setShowAdd(true)} className="gap-1.5">
              <Plus className="w-4 h-4" /> Add Proxy
            </Button>
          </div>
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
                /* ── Issue 9: Inline edit row ── */
                if (editingId === proxy.id) {
                  return (
                    <InlineProxyRow
                      key={proxy.id}
                      proxy={proxy}
                      isSuperAdmin={isSuperAdmin}
                      testingId={testingId}
                      onTest={testProxy}
                      onDelete={() => { if (confirm(`Remove proxy ${proxy.ip}?`)) deleteMut.mutate(proxy.id); }}
                      onCancelEdit={() => setEditingId(null)}
                    />
                  );
                }

                const total = (proxy.successCount ?? 0) + (proxy.failCount ?? 0);
                const successPct = total > 0 ? Math.round(proxy.successCount / total * 100) : null;
                return (
                  <tr key={proxy.id} className="border-b last:border-0 hover:bg-muted/30 transition-colors">
                    <td className="px-4 py-2.5 font-mono text-xs">
                      <span>{proxy.ip}:{proxy.port}</span>
                      {proxy.hasAuth && (
                        <Badge variant="outline" className="ml-1.5 text-[10px] px-1 py-0 gap-0.5 bg-purple-500/10 text-purple-600 border-purple-500/25">
                          <KeyRound className="w-2.5 h-2.5" /> Auth
                        </Badge>
                      )}
                    </td>
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
                          variant="ghost" size="icon" className="w-7 h-7" title="Test health"
                          disabled={testingId === proxy.id}
                          onClick={() => testProxy(proxy)}
                        >
                          {testingId === proxy.id ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <TestTube2 className="w-3.5 h-3.5" />}
                        </Button>
                        {isSuperAdmin && (
                          <>
                            {/* Issue 9: Edit button triggers inline edit mode */}
                            <Button
                              variant="ghost" size="icon" className="w-7 h-7" title="Edit inline"
                              onClick={() => setEditingId(proxy.id)}
                            >
                              <Pencil className="w-3.5 h-3.5" />
                            </Button>
                            <Button
                              variant="ghost" size="icon" className="w-7 h-7 text-destructive hover:text-destructive"
                              title="Delete" disabled={deleteMut.isPending}
                              onClick={() => { if (confirm(`Remove proxy ${proxy.ip}?`)) deleteMut.mutate(proxy.id); }}
                            >
                              <Trash2 className="w-3.5 h-3.5" />
                            </Button>
                          </>
                        )}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Dialogs */}
      {showAdd && <ProxyDialog open onClose={() => setShowAdd(false)} />}
      {/* Issue 3: Bulk import dialog */}
      {showBulk && <BulkImportDialog open onClose={() => setShowBulk(false)} />}
    </div>
  );
}
