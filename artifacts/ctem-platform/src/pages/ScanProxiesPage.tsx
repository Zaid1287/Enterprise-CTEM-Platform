import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Plus, Trash2, Pencil, Wifi, WifiOff, Clock, RefreshCw,
  Loader2, TestTube2, Upload, Check, X, KeyRound, Eye, EyeOff,
  ShieldAlert, RotateCcw, Globe, Activity, Server,
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
  country: string | null; asn: string | null; username: string | null; hasAuth: boolean;
  healthScore: number; successCount: number; failCount: number;
  count429: number; count403: number; avgLatencyMs: number | null;
  status: "active" | "cooldown" | "inactive" | "auth_failed"; lastTestedAt: string | null;
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
    active:     { label: "Healthy",     icon: Wifi,        cls: "bg-green-500/15 text-green-600 border-green-500/30"   },
    cooldown:   { label: "Cooling Down",icon: Clock,       cls: "bg-amber-500/15 text-amber-600 border-amber-500/30"   },
    inactive:   { label: "Inactive",    icon: WifiOff,     cls: "bg-red-500/15 text-red-600 border-red-500/30"         },
    auth_failed:{ label: "Auth Failed", icon: ShieldAlert, cls: "bg-orange-500/15 text-orange-600 border-orange-500/30"},
  };
  const s = map[status] ?? { label: status, icon: RefreshCw, cls: "bg-muted text-muted-foreground" };
  const Icon = s.icon;
  return (
    <Badge variant="outline" className={cn("text-xs font-medium gap-1", s.cls)}>
      <Icon className="w-3 h-3" />{s.label}
    </Badge>
  );
}

/* ─── Health Bar ──────────────────────────────────────────────────────── */
function HealthBar({ score }: { score: number }) {
  const color = score >= 70 ? "bg-green-500" : score >= 30 ? "bg-amber-500" : "bg-red-500";
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-1.5 bg-muted rounded-full overflow-hidden min-w-16">
        <div className={cn("h-full rounded-full transition-all", color)} style={{ width: `${Math.min(100, score)}%` }} />
      </div>
      <span className={cn("text-xs font-bold tabular-nums w-8 text-right", score >= 70 ? "text-green-600" : score >= 30 ? "text-amber-500" : "text-red-500")}>
        {score}
      </span>
    </div>
  );
}

/* ─── Stat Card ───────────────────────────────────────────────────────── */
function StatCard({ label, value, icon: Icon, color, sub }: {
  label: string; value: number | string; icon: React.ElementType; color: string; sub?: string;
}) {
  const colorMap: Record<string, { bg: string; icon: string; border: string }> = {
    green:  { bg: "bg-green-500/10",  icon: "text-green-500",  border: "border-l-green-500"  },
    amber:  { bg: "bg-amber-500/10",  icon: "text-amber-500",  border: "border-l-amber-500"  },
    red:    { bg: "bg-red-500/10",    icon: "text-red-500",    border: "border-l-red-500"    },
    orange: { bg: "bg-orange-500/10", icon: "text-orange-500", border: "border-l-orange-500" },
    blue:   { bg: "bg-blue-500/10",   icon: "text-blue-500",   border: "border-l-blue-500"   },
  };
  const c = colorMap[color] ?? colorMap.blue;
  return (
    <div className={cn("rounded-xl border bg-card p-4 flex items-start gap-3 border-l-4", c.border)}>
      <div className={cn("p-2 rounded-lg shrink-0", c.bg)}>
        <Icon className={cn("w-4 h-4", c.icon)} />
      </div>
      <div className="min-w-0 flex-1">
        <p className="text-xs text-muted-foreground">{label}</p>
        <p className={cn("text-2xl font-bold leading-tight mt-0.5 tabular-nums", c.icon)}>{value}</p>
        {sub && <p className="text-xs text-muted-foreground mt-0.5">{sub}</p>}
      </div>
    </div>
  );
}

/* ─── Add / Edit Dialog ──────────────────────────────────────────────── */
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
        : api("/api/scan-proxies", { method: "POST", body: JSON.stringify(body) }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["scan-proxies"] }); toast({ title: isEdit ? "Proxy updated" : "Proxy added" }); onClose(); },
    onError: (e: Error) => toast({ title: "Failed", description: e.message, variant: "destructive" }),
  });

  const handleSubmit = () => {
    if (!ip.trim()) { toast({ title: "IP required", variant: "destructive" }); return; }
    const body: Record<string, any> = {
      ip: ip.trim(), port: parseInt(port, 10), label: label || undefined,
      type, country: country || undefined, asn: asn || undefined, username: username || undefined,
    };
    if (password) body.password = password;
    saveMut.mutate(body);
  };

  return (
    <Dialog open={open} onOpenChange={v => { if (!v) onClose(); }}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Globe className="w-4 h-4 text-blue-500" />
            {isEdit ? "Edit Proxy" : "Add Proxy"}
          </DialogTitle>
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
                  <Input type={showPwd ? "text" : "password"} placeholder={isEdit ? "leave blank to keep" : "pass"} value={password} onChange={e => setPassword(e.target.value)} autoComplete="new-password" className="pr-8" />
                  <button type="button" className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground" onClick={() => setShowPwd(v => !v)}>
                    {showPwd ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                  </button>
                </div>
              </div>
            </div>
            {isEdit && initial?.hasAuth && !password && (
              <p className="text-xs text-muted-foreground mt-1.5">Credentials already set. Leave blank to keep the existing password.</p>
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

/* ─── Bulk Import Dialog ─────────────────────────────────────────────── */
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
      const res = await api<BulkResult>("/api/scan-proxies/bulk", { method: "POST", body: JSON.stringify({ proxies: text }) });
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
          <DialogTitle className="flex items-center gap-2">
            <Upload className="w-4 h-4 text-blue-500" /> Bulk Import Proxies
          </DialogTitle>
        </DialogHeader>
        <div className="space-y-4 py-2">
          {!result ? (
            <>
              <p className="text-sm text-muted-foreground">Paste one proxy per line. Supported formats:</p>
              <div className="bg-muted/50 rounded-lg px-3 py-2 font-mono text-xs text-muted-foreground space-y-0.5">
                <div>ip:port</div>
                <div>ip:port:username:password</div>
                <div>ip:port:username:password:label</div>
              </div>
              <Textarea placeholder={"1.2.3.4:8080\n5.6.7.8:3128:user:secret\n9.10.11.12:8888:user:pass:Datacenter-US"} value={text} onChange={e => setText(e.target.value)} rows={10} className="font-mono text-xs" />
              <p className="text-xs text-muted-foreground">Each proxy will be health-checked (TCP ping) before import. This may take a moment.</p>
            </>
          ) : (
            <div className="space-y-3">
              <div className="grid grid-cols-3 gap-3 text-center">
                <div className="rounded-xl border bg-green-500/10 p-4">
                  <p className="text-3xl font-bold text-green-600">{result.imported}</p>
                  <p className="text-xs text-muted-foreground mt-1">Imported</p>
                </div>
                <div className="rounded-xl border bg-red-500/10 p-4">
                  <p className="text-3xl font-bold text-red-500">{result.failed}</p>
                  <p className="text-xs text-muted-foreground mt-1">Failed</p>
                </div>
                <div className="rounded-xl border bg-muted p-4">
                  <p className="text-3xl font-bold">{result.total}</p>
                  <p className="text-xs text-muted-foreground mt-1">Total</p>
                </div>
              </div>
              <div className="max-h-48 overflow-y-auto space-y-1">
                {result.results.map((r, i) => (
                  <div key={i} className={cn("flex items-center gap-2 text-xs px-2 py-1 rounded", r.ok ? "bg-green-500/5" : "bg-red-500/5")}>
                    {r.ok ? <Check className="w-3 h-3 text-green-600 shrink-0" /> : <X className="w-3 h-3 text-red-500 shrink-0" />}
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

/* ─── Fix Auth Dialog ────────────────────────────────────────────────── */
function FixAuthDialog({ open, onClose, proxy }: { open: boolean; onClose: () => void; proxy: Proxy }) {
  const qc = useQueryClient();
  const { toast } = useToast();
  const [username, setUsername] = useState(proxy.username ?? "");
  const [password, setPassword] = useState("");
  const [showPwd, setShowPwd]   = useState(false);

  const fixMut = useMutation({
    mutationFn: (body: object) => api(`/api/scan-proxies/${proxy.id}`, { method: "PATCH", body: JSON.stringify(body) }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["scan-proxies"] }); toast({ title: "Proxy re-enabled", description: "Status reset to active with health score 50." }); onClose(); },
    onError: (e: Error) => toast({ title: "Failed", description: e.message, variant: "destructive" }),
  });

  return (
    <Dialog open={open} onOpenChange={v => { if (!v) onClose(); }}>
      <DialogContent className="max-w-sm">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-orange-500" /> Fix Credentials & Re-enable
          </DialogTitle>
        </DialogHeader>
        <div className="space-y-4 py-2">
          <div className="rounded-lg border border-orange-500/30 bg-orange-500/10 px-3 py-2.5 text-xs text-orange-700 dark:text-orange-400">
            Proxy <span className="font-mono font-semibold">{proxy.ip}:{proxy.port}</span> failed authentication. Update the credentials below and click Re-enable to restore it.
          </div>
          <div className="space-y-1.5">
            <Label>Username</Label>
            <Input placeholder="user" value={username} onChange={e => setUsername(e.target.value)} autoComplete="off" />
          </div>
          <div className="space-y-1.5">
            <Label>New Password <span className="text-destructive">*</span></Label>
            <div className="relative">
              <Input type={showPwd ? "text" : "password"} placeholder="new password" value={password} onChange={e => setPassword(e.target.value)} autoComplete="new-password" className="pr-8" />
              <button type="button" className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground" onClick={() => setShowPwd(v => !v)}>
                {showPwd ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
              </button>
            </div>
          </div>
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={onClose} disabled={fixMut.isPending}>Cancel</Button>
          <Button onClick={() => { if (!password.trim()) { toast({ title: "New password required", variant: "destructive" }); return; } fixMut.mutate({ username: username || null, password, resetAuthFailed: true }); }} disabled={fixMut.isPending} className="gap-1.5">
            {fixMut.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <RotateCcw className="w-4 h-4" />}
            Re-enable Proxy
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

/* ─── Inline Editable Row ────────────────────────────────────────────── */
interface InlineEdit { ip: string; port: string; label: string; type: string; country: string; asn: string; username: string; password: string; }

function InlineProxyRow({ proxy, testingId, onTest, onDelete, onCancelEdit }: {
  proxy: Proxy; testingId: number | null;
  onTest: (p: Proxy) => void; onDelete: (p: Proxy) => void; onCancelEdit: () => void;
}) {
  const qc = useQueryClient();
  const { toast } = useToast();
  const [row, setRow] = useState<InlineEdit>({
    ip: proxy.ip, port: String(proxy.port), label: proxy.label ?? "", type: proxy.type,
    country: proxy.country ?? "", asn: proxy.asn ?? "", username: proxy.username ?? "", password: "",
  });
  const [saving, setSaving] = useState(false);

  const save = async () => {
    if (!row.ip.trim()) { toast({ title: "IP required", variant: "destructive" }); return; }
    setSaving(true);
    try {
      const body: Record<string, any> = {
        ip: row.ip.trim(), port: parseInt(row.port, 10), label: row.label || null, type: row.type,
        country: row.country || null, asn: row.asn || null, username: row.username || null,
      };
      if (row.password) body.password = row.password;
      await api(`/api/scan-proxies/${proxy.id}`, { method: "PATCH", body: JSON.stringify(body) });
      qc.invalidateQueries({ queryKey: ["scan-proxies"] });
      toast({ title: "Proxy updated" });
      onCancelEdit();
    } catch (e: any) {
      toast({ title: "Update failed", description: e.message, variant: "destructive" });
    } finally { setSaving(false); }
  };

  const cell = "px-4 py-2";
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
      <td className={`${cell} text-right`}>
        <span className={cn("font-bold text-sm tabular-nums", proxy.healthScore >= 70 ? "text-green-600" : proxy.healthScore >= 30 ? "text-amber-500" : "text-red-500")}>
          {proxy.healthScore}
        </span>
      </td>
      <td className={`${cell} text-right text-xs text-muted-foreground`}>—</td>
      <td className={`${cell} text-right text-xs`}>{proxy.count429}</td>
      <td className={`${cell} text-right text-xs`}>{proxy.count403}</td>
      <td className={`${cell} text-right text-xs text-muted-foreground`}>{proxy.avgLatencyMs != null ? `${proxy.avgLatencyMs}ms` : "—"}</td>
      <td className={cell} colSpan={2}>
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

/* ─── Type Badge ──────────────────────────────────────────────────────── */
const TYPE_COLORS: Record<string, string> = {
  datacenter:  "bg-blue-500/10 text-blue-600 border-blue-500/25",
  residential: "bg-green-500/10 text-green-600 border-green-500/25",
  isp:         "bg-purple-500/10 text-purple-600 border-purple-500/25",
  mobile:      "bg-cyan-500/10 text-cyan-600 border-cyan-500/25",
  socks5:      "bg-orange-500/10 text-orange-600 border-orange-500/25",
  http:        "bg-slate-500/10 text-slate-600 border-slate-500/25",
};

/* ─── Main Page ───────────────────────────────────────────────────────── */
export default function ScanProxiesPage() {
  const { user } = useAuth();
  const isSuperAdmin = user?.role === "super_admin";
  const { toast } = useToast();
  const qc = useQueryClient();
  const [showAdd, setShowAdd]           = useState(false);
  const [showBulk, setShowBulk]         = useState(false);
  const [editingId, setEditingId]       = useState<number | null>(null);
  const [fixAuthProxy, setFixAuthProxy] = useState<Proxy | null>(null);
  const [testingId, setTestingId]       = useState<number | null>(null);

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
    } catch { toast({ title: "Health check failed", variant: "destructive" }); }
    finally { setTestingId(null); }
  };

  const activeCount     = proxies.filter(p => p.status === "active").length;
  const cooldownCount   = proxies.filter(p => p.status === "cooldown").length;
  const inactiveCount   = proxies.filter(p => p.status === "inactive").length;
  const authFailedCount = proxies.filter(p => p.status === "auth_failed").length;
  const avgHealth = proxies.length > 0 ? Math.round(proxies.reduce((s, p) => s + p.healthScore, 0) / proxies.length) : 0;

  return (
    <div className="p-6 space-y-6">
      {/* ── Dialogs ── */}
      <ProxyDialog open={showAdd} onClose={() => setShowAdd(false)} />
      <BulkImportDialog open={showBulk} onClose={() => setShowBulk(false)} />
      {fixAuthProxy && (
        <FixAuthDialog open={!!fixAuthProxy} onClose={() => setFixAuthProxy(null)} proxy={fixAuthProxy} />
      )}

      {/* ── Header ── */}
      <div className="flex items-start justify-between gap-4">
        <div className="flex items-center gap-4">
          <div className="p-3 rounded-xl bg-blue-500/15 border border-blue-500/25">
            <Globe className="w-6 h-6 text-blue-500" />
          </div>
          <div>
            <h1 className="text-2xl font-bold tracking-tight">Proxy / IP Pool Management</h1>
            <p className="text-sm text-muted-foreground mt-0.5">
              Configure and health-check outbound proxies used by the scan orchestration engine
            </p>
          </div>
        </div>
        {isSuperAdmin && (
          <div className="flex items-center gap-2 shrink-0">
            <Button variant="outline" onClick={() => setShowBulk(true)} className="gap-1.5">
              <Upload className="w-4 h-4" /> Bulk Import
            </Button>
            <Button onClick={() => setShowAdd(true)} className="gap-1.5">
              <Plus className="w-4 h-4" /> Add Proxy
            </Button>
          </div>
        )}
      </div>

      {/* ── Stat Cards ── */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-4">
        {isLoading ? (
          Array.from({ length: 5 }).map((_, i) => <Skeleton key={i} className="h-24 rounded-xl" />)
        ) : (
          <>
            <StatCard label="Total Proxies"   value={proxies.length}  icon={Server}  color="blue"   sub="in pool" />
            <StatCard label="Healthy"         value={activeCount}     icon={Wifi}    color="green"  sub="accepting requests" />
            <StatCard label="Cooling Down"    value={cooldownCount}   icon={Clock}   color="amber"  sub="temporary pause" />
            <StatCard label="Inactive"        value={inactiveCount}   icon={WifiOff} color="red"    sub="health check failed" />
            <StatCard label="Avg Health Score" value={proxies.length > 0 ? avgHealth : "—"} icon={Activity} color={avgHealth >= 70 ? "green" : avgHealth >= 40 ? "amber" : "red"} sub="pool average" />
          </>
        )}
      </div>

      {/* ── Auth Failed Banner ── */}
      {authFailedCount > 0 && (
        <div className="rounded-xl border border-orange-500/30 bg-orange-500/10 px-5 py-3 flex items-center gap-3">
          <ShieldAlert className="w-5 h-5 text-orange-500 shrink-0" />
          <div className="flex-1">
            <p className="text-sm font-semibold text-orange-600">{authFailedCount} proxy{authFailedCount > 1 ? "ies" : ""} failed authentication</p>
            <p className="text-xs text-orange-600/80 mt-0.5">Click the re-enable button in the table below to update credentials and restore them.</p>
          </div>
        </div>
      )}

      {/* ── Proxy Table ── */}
      <div className="rounded-xl border bg-card overflow-hidden">
        <div className="px-5 py-4 border-b flex items-center justify-between bg-muted/20">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-blue-500/15 border border-blue-500/25">
              <Server className="w-4 h-4 text-blue-500" />
            </div>
            <div>
              <h2 className="text-sm font-semibold">Proxy Pool</h2>
              <p className="text-xs text-muted-foreground">{proxies.length} proxy{proxies.length !== 1 ? "ies" : ""} configured · auto-refreshes every 30s</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Badge variant="outline" className="bg-green-500/10 text-green-600 border-green-500/25 gap-1 text-xs">
              <Wifi className="w-3 h-3" /> {activeCount} healthy
            </Badge>
            {authFailedCount > 0 && (
              <Badge variant="outline" className="bg-orange-500/10 text-orange-600 border-orange-500/25 gap-1 text-xs">
                <ShieldAlert className="w-3 h-3" /> {authFailedCount} auth failed
              </Badge>
            )}
          </div>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b bg-muted/40 text-xs text-muted-foreground">
                <th className="px-4 py-2.5 text-left font-medium whitespace-nowrap">IP : Port</th>
                <th className="px-4 py-2.5 text-left font-medium">Label</th>
                <th className="px-4 py-2.5 text-left font-medium">Class</th>
                <th className="px-4 py-2.5 text-left font-medium">Country</th>
                <th className="px-4 py-2.5 text-left font-medium">ASN</th>
                <th className="px-4 py-2.5 text-right font-medium">Health</th>
                <th className="px-4 py-2.5 text-right font-medium">Success %</th>
                <th className="px-4 py-2.5 text-right font-medium">429s</th>
                <th className="px-4 py-2.5 text-right font-medium">403s</th>
                <th className="px-4 py-2.5 text-right font-medium whitespace-nowrap">Avg Latency</th>
                <th className="px-4 py-2.5 text-left font-medium">Status</th>
                <th className="px-4 py-2.5 text-left font-medium whitespace-nowrap">Last Tested</th>
                <th className="px-4 py-2.5 text-right font-medium">Actions</th>
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
                <tr>
                  <td colSpan={13} className="px-4 py-16 text-center">
                    <Globe className="w-10 h-10 text-muted-foreground/20 mx-auto mb-3" />
                    <p className="text-sm font-medium text-muted-foreground">No proxies configured yet</p>
                    <p className="text-xs text-muted-foreground/60 mt-1">Add a proxy IP to start routing scan traffic through it</p>
                    {isSuperAdmin && (
                      <Button size="sm" className="mt-4 gap-1.5" onClick={() => setShowAdd(true)}>
                        <Plus className="w-3.5 h-3.5" /> Add First Proxy
                      </Button>
                    )}
                  </td>
                </tr>
              ) : proxies.map(proxy => {
                if (editingId === proxy.id) {
                  return (
                    <InlineProxyRow
                      key={proxy.id} proxy={proxy} testingId={testingId}
                      onTest={testProxy}
                      onDelete={() => { if (confirm(`Remove proxy ${proxy.ip}?`)) deleteMut.mutate(proxy.id); }}
                      onCancelEdit={() => setEditingId(null)}
                    />
                  );
                }

                const tot = (proxy.successCount ?? 0) + (proxy.failCount ?? 0);
                const successPct = tot > 0 ? Math.round(proxy.successCount / tot * 100) : null;
                const typeColor = TYPE_COLORS[proxy.type] ?? "bg-muted text-muted-foreground";

                return (
                  <tr key={proxy.id} className={cn(
                    "border-b last:border-0 hover:bg-muted/30 transition-colors",
                    proxy.status === "auth_failed" && "bg-orange-500/5"
                  )}>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-1.5 font-mono text-xs">
                        <span className="font-semibold">{proxy.ip}</span>
                        <span className="text-muted-foreground">:{proxy.port}</span>
                        {proxy.hasAuth && (
                          <Badge variant="outline" className="ml-0.5 text-[10px] px-1 py-0 gap-0.5 bg-purple-500/10 text-purple-600 border-purple-500/25">
                            <KeyRound className="w-2.5 h-2.5" /> Auth
                          </Badge>
                        )}
                      </div>
                    </td>
                    <td className="px-4 py-3 text-xs text-muted-foreground">{proxy.label ?? "—"}</td>
                    <td className="px-4 py-3">
                      <Badge variant="outline" className={cn("text-xs capitalize", typeColor)}>{proxy.type}</Badge>
                    </td>
                    <td className="px-4 py-3 text-xs font-medium">{proxy.country ?? "—"}</td>
                    <td className="px-4 py-3 text-xs text-muted-foreground">{proxy.asn ?? "—"}</td>
                    <td className="px-4 py-3 min-w-32">
                      <HealthBar score={proxy.healthScore} />
                    </td>
                    <td className="px-4 py-3 text-right text-xs">
                      {successPct != null ? (
                        <span className={cn("font-semibold", successPct >= 80 ? "text-green-600" : successPct >= 50 ? "text-amber-500" : "text-red-500")}>
                          {successPct}%
                        </span>
                      ) : <span className="text-muted-foreground">—</span>}
                    </td>
                    <td className="px-4 py-3 text-right text-xs">
                      {proxy.count429 > 0 ? <span className="text-amber-500 font-semibold">{proxy.count429}</span> : <span className="text-muted-foreground">0</span>}
                    </td>
                    <td className="px-4 py-3 text-right text-xs">
                      {proxy.count403 > 0 ? <span className="text-red-500 font-semibold">{proxy.count403}</span> : <span className="text-muted-foreground">0</span>}
                    </td>
                    <td className="px-4 py-3 text-right text-xs text-muted-foreground">
                      {proxy.avgLatencyMs != null ? `${proxy.avgLatencyMs}ms` : "—"}
                    </td>
                    <td className="px-4 py-3"><StatusBadge status={proxy.status} /></td>
                    <td className="px-4 py-3 text-xs text-muted-foreground">
                      {proxy.lastTestedAt ? new Date(proxy.lastTestedAt).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }) : "Never"}
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center justify-end gap-0.5">
                        <Button variant="ghost" size="icon" className="w-7 h-7" title="Test health" disabled={testingId === proxy.id} onClick={() => testProxy(proxy)}>
                          {testingId === proxy.id ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <TestTube2 className="w-3.5 h-3.5" />}
                        </Button>
                        {isSuperAdmin && (
                          <>
                            {proxy.status === "auth_failed" && (
                              <Button variant="ghost" size="icon" className="w-7 h-7 text-orange-500 hover:text-orange-600 hover:bg-orange-500/10" title="Fix Credentials & Re-enable" onClick={() => setFixAuthProxy(proxy)}>
                                <RotateCcw className="w-3.5 h-3.5" />
                              </Button>
                            )}
                            <Button variant="ghost" size="icon" className="w-7 h-7" title="Edit inline" onClick={() => setEditingId(proxy.id)}>
                              <Pencil className="w-3.5 h-3.5" />
                            </Button>
                            <Button variant="ghost" size="icon" className="w-7 h-7 text-red-500 hover:text-red-600 hover:bg-red-500/10" title="Remove proxy" onClick={() => { if (confirm(`Remove proxy ${proxy.ip}?`)) deleteMut.mutate(proxy.id); }}>
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
    </div>
  );
}
