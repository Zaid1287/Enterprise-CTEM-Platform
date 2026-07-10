import { useState, useEffect } from "react";
import {
  Shield, Plus, Pencil, Trash2, Loader2, CheckCircle2,
  XCircle, Globe, Info, RefreshCw, AlertTriangle, Network,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Switch } from "@/components/ui/switch";
import {
  Dialog, DialogContent, DialogHeader, DialogTitle,
  DialogFooter, DialogDescription,
} from "@/components/ui/dialog";
import { Badge } from "@/components/ui/badge";
import { useToast } from "@/hooks/use-toast";
import { apiFetch } from "@/lib/apiFetch";
import { cn } from "@/lib/utils";

// ── CIDR helpers (pure JS — no backend round-trip needed for previews) ─────────
function ip2int(ip: string): number {
  const p = ip.split(".").map(Number);
  return (((p[0]! << 24) | (p[1]! << 16) | (p[2]! << 8) | p[3]!) >>> 0);
}
function int2ip(n: number): string {
  return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(".");
}
function cidrToRange(cidr: string): { start: string; end: string; count: number } | null {
  const m = cidr.trim().match(/^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/);
  if (!m) return null;
  const bits = parseInt(m[2]!, 10);
  if (bits < 0 || bits > 32) return null;
  const parts = m[1]!.split(".").map(Number);
  if (parts.some(p => isNaN(p) || p < 0 || p > 255)) return null;
  const base = ((parts[0]! << 24) | (parts[1]! << 16) | (parts[2]! << 8) | parts[3]!) >>> 0;
  const mask = bits === 0 ? 0 : ((0xFFFFFFFF << (32 - bits)) >>> 0);
  const start = (base & mask) >>> 0;
  const end   = (start | (~mask >>> 0)) >>> 0;
  return { start: int2ip(start), end: int2ip(end), count: end - start + 1 };
}
function fmtCount(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M IPs`;
  if (n >= 1_000)     return `${(n / 1_000).toFixed(0)}K IPs`;
  return `${n} IPs`;
}

// ── Types ─────────────────────────────────────────────────────────────────────
interface CdnEntry {
  id: number;
  label: string;
  cidr: string;
  ipStart: string;
  ipEnd: string;
  description: string | null;
  isActive: boolean;
  isBuiltIn: boolean;
  createdAt: string;
  updatedAt: string;
}

const PROVIDER_COLORS: Record<string, string> = {
  Cloudflare:  "bg-orange-500/10 text-orange-400 border-orange-500/25",
  Akamai:      "bg-blue-500/10   text-blue-400   border-blue-500/25",
  CloudFront:  "bg-yellow-500/10 text-yellow-400 border-yellow-500/25",
  GoDaddy:     "bg-green-500/10  text-green-400  border-green-500/25",
  Namecheap:   "bg-cyan-500/10   text-cyan-400   border-cyan-500/25",
  Sedo:        "bg-purple-500/10 text-purple-400 border-purple-500/25",
  Bodis:       "bg-pink-500/10   text-pink-400   border-pink-500/25",
  "Dan.com":   "bg-rose-500/10   text-rose-400   border-rose-500/25",
};
function providerColor(label: string): string {
  return PROVIDER_COLORS[label] ?? "bg-muted/50 text-muted-foreground border-border";
}

// ── Empty form ────────────────────────────────────────────────────────────────
const EMPTY_FORM = { label: "", cidr: "", description: "", isActive: true };

export default function CdnWhitelistPage() {
  const { toast } = useToast();
  const [entries, setEntries]     = useState<CdnEntry[]>([]);
  const [loading, setLoading]     = useState(true);
  const [saving, setSaving]       = useState(false);
  const [deleting, setDeleting]   = useState<number | null>(null);

  const [showDialog, setShowDialog]       = useState(false);
  const [editEntry, setEditEntry]         = useState<CdnEntry | null>(null);
  const [form, setForm]                   = useState(EMPTY_FORM);
  const [cidrPreview, setCidrPreview]     = useState<ReturnType<typeof cidrToRange>>(null);
  const [confirmDelete, setConfirmDelete] = useState<CdnEntry | null>(null);

  // ── Load ───────────────────────────────────────────────────────────────────
  async function load() {
    setLoading(true);
    try {
      const data = await apiFetch<CdnEntry[]>("/api/cdn-whitelist");
      setEntries(data);
    } catch {
      toast({ title: "Failed to load CDN whitelist", variant: "destructive" });
    } finally {
      setLoading(false);
    }
  }
  useEffect(() => { load(); }, []);

  // ── CIDR live preview ─────────────────────────────────────────────────────
  useEffect(() => {
    setCidrPreview(cidrToRange(form.cidr));
  }, [form.cidr]);

  // ── Open dialog ───────────────────────────────────────────────────────────
  function openAdd() {
    setEditEntry(null);
    setForm(EMPTY_FORM);
    setShowDialog(true);
  }
  function openEdit(e: CdnEntry) {
    setEditEntry(e);
    setForm({ label: e.label, cidr: e.cidr, description: e.description ?? "", isActive: e.isActive });
    setShowDialog(true);
  }

  // ── Save (create or update) ───────────────────────────────────────────────
  async function handleSave() {
    if (!form.label.trim() || !form.cidr.trim()) {
      toast({ title: "Label and CIDR are required", variant: "destructive" }); return;
    }
    if (!cidrPreview) {
      toast({ title: "Invalid CIDR — use format like 151.101.0.0/16", variant: "destructive" }); return;
    }
    setSaving(true);
    try {
      const url    = editEntry ? `/api/cdn-whitelist/${editEntry.id}` : "/api/cdn-whitelist";
      const method = editEntry ? "PATCH" : "POST";
      const saved  = await apiFetch<CdnEntry>(url, {
        method,
        body: JSON.stringify({ label: form.label, cidr: form.cidr, description: form.description || null, isActive: form.isActive }),
      });
      if (editEntry) {
        setEntries(prev => prev.map(e => e.id === saved.id ? saved : e));
        toast({ title: "Entry updated" });
      } else {
        setEntries(prev => [...prev, saved]);
        toast({ title: "Entry added — takes effect on next brand threat scan" });
      }
      setShowDialog(false);
    } catch (err: any) {
      toast({ title: err?.message ?? "Failed to save entry", variant: "destructive" });
    } finally {
      setSaving(false);
    }
  }

  // ── Toggle active ─────────────────────────────────────────────────────────
  async function toggleActive(e: CdnEntry) {
    try {
      const updated = await apiFetch<CdnEntry>(`/api/cdn-whitelist/${e.id}`, {
        method: "PATCH",
        body: JSON.stringify({ isActive: !e.isActive }),
      });
      setEntries(prev => prev.map(x => x.id === updated.id ? updated : x));
    } catch {
      toast({ title: "Failed to update entry", variant: "destructive" });
    }
  }

  // ── Delete ────────────────────────────────────────────────────────────────
  async function handleDelete(e: CdnEntry) {
    setDeleting(e.id);
    try {
      await apiFetch(`/api/cdn-whitelist/${e.id}`, { method: "DELETE" });
      setEntries(prev => prev.filter(x => x.id !== e.id));
      toast({ title: "Entry deleted" });
    } catch {
      toast({ title: "Failed to delete entry", variant: "destructive" });
    } finally {
      setDeleting(null);
      setConfirmDelete(null);
    }
  }

  // ── Stats ─────────────────────────────────────────────────────────────────
  const total    = entries.length;
  const active   = entries.filter(e => e.isActive).length;
  const builtIn  = entries.filter(e => e.isBuiltIn).length;
  const custom   = entries.filter(e => !e.isBuiltIn).length;

  // Group by label for display
  const grouped = entries.reduce<Record<string, CdnEntry[]>>((acc, e) => {
    (acc[e.label] ??= []).push(e);
    return acc;
  }, {});

  return (
    <div className="p-6 space-y-6">
      {/* ── Header ────────────────────────────────────────────────────────── */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <Shield className="w-5 h-5 text-primary" />
            <h1 className="text-xl font-bold">CDN Whitelist</h1>
            <Badge variant="outline" className="text-[10px] font-mono">super_admin</Badge>
          </div>
          <p className="text-sm text-muted-foreground max-w-2xl">
            IP ranges listed here are recognised as CDN or domain-parking infrastructure.
            During brand threat scans, any typosquatted domain whose DNS A record resolves
            into one of these ranges receives a <strong className="text-foreground">−20 risk score deduction</strong>,
            reducing false-positive alerts for passively-parked domains.
          </p>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <Button variant="outline" size="sm" onClick={load} disabled={loading}>
            <RefreshCw className={cn("w-3.5 h-3.5 mr-1.5", loading && "animate-spin")} /> Refresh
          </Button>
          <Button size="sm" onClick={openAdd}>
            <Plus className="w-3.5 h-3.5 mr-1.5" /> Add Range
          </Button>
        </div>
      </div>

      {/* ── How it works ──────────────────────────────────────────────────── */}
      <div className="bg-blue-500/5 border border-blue-500/20 rounded-xl p-4 text-sm">
        <div className="flex items-center gap-2 mb-2 font-semibold text-blue-300">
          <Info className="w-4 h-4" /> How CDN Whitelisting Works in ASM
        </div>
        <div className="text-muted-foreground space-y-1 text-xs leading-relaxed">
          <p><strong className="text-foreground">1. Permutation scan</strong> — dnstwist generates lookalike domains (e.g. g00gle.com, gooogle.com) and resolves their DNS A records.</p>
          <p><strong className="text-foreground">2. IP range check</strong> — each resolved IP is checked against this whitelist using integer range comparison (O(n) lookup, extremely fast).</p>
          <p><strong className="text-foreground">3. Score deduction</strong> — domains parking on CDN IPs get <code className="bg-muted px-1 rounded">−20</code> from their risk score, because CDN providers (Cloudflare, Akamai, CloudFront) and dedicated parking services (Sedo, GoDaddy) host thousands of passive registrations that are monetised with ads, not used for phishing.</p>
          <p><strong className="text-foreground">4. Active threats still fire</strong> — the deduction only applies to CDN-parked domains. If VirusTotal flags a domain as malicious (+40) or it appears in PhishTank (+50), the net score is still well above the 60-point "suspicious" threshold, so real threats are never suppressed.</p>
          <p><strong className="text-foreground">5. Changes take effect immediately</strong> — the next brand threat scan loads this table fresh from the database at scan start.</p>
        </div>
      </div>

      {/* ── Stats ─────────────────────────────────────────────────────────── */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {[
          { label: "Total Ranges", value: total,   icon: Network,       color: "text-primary" },
          { label: "Active",       value: active,  icon: CheckCircle2,  color: "text-green-400" },
          { label: "Built-in",     value: builtIn, icon: Shield,        color: "text-blue-400" },
          { label: "Custom",       value: custom,  icon: Plus,          color: "text-violet-400" },
        ].map(s => (
          <div key={s.label} className="bg-card border border-border rounded-xl p-4">
            <div className="flex items-center gap-2 mb-1">
              <s.icon className={cn("w-4 h-4", s.color)} />
              <span className="text-xs text-muted-foreground">{s.label}</span>
            </div>
            <p className={cn("text-2xl font-bold tabular-nums", s.color)}>{s.value}</p>
          </div>
        ))}
      </div>

      {/* ── Table ─────────────────────────────────────────────────────────── */}
      {loading ? (
        <div className="flex items-center justify-center h-40 gap-2 text-muted-foreground">
          <Loader2 className="w-4 h-4 animate-spin" /> Loading…
        </div>
      ) : entries.length === 0 ? (
        <div className="border border-dashed border-border rounded-xl p-12 text-center">
          <Network className="w-10 h-10 text-muted-foreground/30 mx-auto mb-3" />
          <p className="text-muted-foreground">No CDN ranges configured yet.</p>
          <Button size="sm" className="mt-4" onClick={openAdd}><Plus className="w-3.5 h-3.5 mr-1" />Add first range</Button>
        </div>
      ) : (
        <div className="border border-border rounded-xl overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-muted/30 text-muted-foreground text-xs uppercase tracking-wider">
              <tr>
                <th className="text-left px-4 py-3">Provider / Label</th>
                <th className="text-left px-4 py-3">CIDR</th>
                <th className="text-left px-4 py-3 hidden md:table-cell">IP Range</th>
                <th className="text-left px-4 py-3 hidden lg:table-cell">Size</th>
                <th className="text-left px-4 py-3 hidden lg:table-cell">Description</th>
                <th className="text-left px-4 py-3">Type</th>
                <th className="text-center px-4 py-3">Active</th>
                <th className="px-4 py-3" />
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {entries.map(e => {
                const range = cidrToRange(e.cidr);
                return (
                  <tr key={e.id} className={cn("hover:bg-muted/20 transition-colors", !e.isActive && "opacity-50")}>
                    <td className="px-4 py-3">
                      <span className={cn("inline-flex items-center gap-1 px-2 py-0.5 rounded-md border text-xs font-semibold", providerColor(e.label))}>
                        {e.label}
                      </span>
                    </td>
                    <td className="px-4 py-3 font-mono text-xs">{e.cidr}</td>
                    <td className="px-4 py-3 font-mono text-xs text-muted-foreground hidden md:table-cell">
                      {e.ipStart} – {e.ipEnd}
                    </td>
                    <td className="px-4 py-3 text-xs text-muted-foreground hidden lg:table-cell">
                      {range ? fmtCount(range.count) : "—"}
                    </td>
                    <td className="px-4 py-3 text-xs text-muted-foreground hidden lg:table-cell max-w-[200px] truncate">
                      {e.description ?? <span className="italic opacity-50">No description</span>}
                    </td>
                    <td className="px-4 py-3">
                      {e.isBuiltIn
                        ? <Badge variant="outline" className="text-[10px] text-blue-400 border-blue-500/30">Built-in</Badge>
                        : <Badge variant="outline" className="text-[10px] text-violet-400 border-violet-500/30">Custom</Badge>
                      }
                    </td>
                    <td className="px-4 py-3 text-center">
                      <Switch checked={e.isActive} onCheckedChange={() => toggleActive(e)} />
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center justify-end gap-1">
                        <Button variant="ghost" size="icon" className="w-7 h-7" onClick={() => openEdit(e)} title="Edit">
                          <Pencil className="w-3.5 h-3.5" />
                        </Button>
                        <Button variant="ghost" size="icon" className="w-7 h-7 text-destructive hover:text-destructive"
                          onClick={() => setConfirmDelete(e)}
                          disabled={deleting === e.id}
                          title="Delete"
                        >
                          {deleting === e.id ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Trash2 className="w-3.5 h-3.5" />}
                        </Button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {/* ── Grouped summary ───────────────────────────────────────────────── */}
      {!loading && entries.length > 0 && (
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-3">
          {Object.entries(grouped).map(([label, items]) => (
            <div key={label} className="border border-border rounded-xl p-4">
              <div className="flex items-center justify-between mb-2">
                <span className={cn("text-xs font-semibold px-2 py-0.5 rounded border", providerColor(label))}>{label}</span>
                <span className="text-xs text-muted-foreground">{items.length} range{items.length !== 1 ? "s" : ""}</span>
              </div>
              <div className="text-xs text-muted-foreground space-y-0.5">
                {items.map(i => (
                  <div key={i.id} className="font-mono flex items-center gap-1">
                    {i.isActive
                      ? <CheckCircle2 className="w-2.5 h-2.5 text-green-400 shrink-0" />
                      : <XCircle className="w-2.5 h-2.5 text-muted-foreground/40 shrink-0" />
                    }
                    {i.cidr}
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* ── Add / Edit dialog ─────────────────────────────────────────────── */}
      <Dialog open={showDialog} onOpenChange={setShowDialog}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>{editEntry ? "Edit CDN Range" : "Add CDN Range"}</DialogTitle>
            <DialogDescription>
              Any domain whose A record falls in this range gets a −20 risk score deduction during brand threat scans.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4 py-2">
            {/* Label */}
            <div className="space-y-1.5">
              <Label>Provider / Label <span className="text-destructive">*</span></Label>
              <Input
                placeholder="e.g. Fastly, Azure CDN, My Company Proxy"
                value={form.label}
                onChange={e => setForm(v => ({ ...v, label: e.target.value }))}
              />
              <p className="text-xs text-muted-foreground">Used to group and identify ranges in the table.</p>
            </div>

            {/* CIDR */}
            <div className="space-y-1.5">
              <Label>CIDR Range <span className="text-destructive">*</span></Label>
              <Input
                placeholder="e.g. 151.101.0.0/16"
                value={form.cidr}
                onChange={e => setForm(v => ({ ...v, cidr: e.target.value }))}
                className={cn(form.cidr && !cidrPreview && "border-destructive")}
              />
              {/* Live preview */}
              {form.cidr && (
                cidrPreview ? (
                  <div className="bg-green-500/5 border border-green-500/20 rounded-lg px-3 py-2 text-xs space-y-1">
                    <div className="flex items-center gap-1.5 text-green-400 font-semibold">
                      <CheckCircle2 className="w-3 h-3" /> Valid CIDR — {fmtCount(cidrPreview.count)}
                    </div>
                    <div className="font-mono text-muted-foreground">
                      {cidrPreview.start} → {cidrPreview.end}
                    </div>
                  </div>
                ) : (
                  <div className="bg-destructive/5 border border-destructive/20 rounded-lg px-3 py-2 text-xs text-destructive flex items-center gap-1.5">
                    <XCircle className="w-3 h-3" /> Invalid CIDR — use format x.x.x.x/prefix (e.g. 151.101.0.0/16)
                  </div>
                )
              )}
              <p className="text-xs text-muted-foreground">
                Find ranges: <a href="https://search.arin.net" target="_blank" rel="noopener noreferrer" className="underline">ARIN</a> ·{" "}
                <a href="https://ip-ranges.amazonaws.com/ip-ranges.json" target="_blank" rel="noopener noreferrer" className="underline">AWS</a> ·{" "}
                <a href="https://api.fastly.com/public-ip-list" target="_blank" rel="noopener noreferrer" className="underline">Fastly</a> ·{" "}
                <a href="https://www.cloudflare.com/ips-v4" target="_blank" rel="noopener noreferrer" className="underline">Cloudflare</a>
              </p>
            </div>

            {/* Description */}
            <div className="space-y-1.5">
              <Label>Description <span className="text-muted-foreground text-xs">(optional)</span></Label>
              <Textarea
                placeholder="e.g. Fastly CDN — used for domain parking and static asset delivery"
                value={form.description}
                onChange={e => setForm(v => ({ ...v, description: e.target.value }))}
                rows={2}
                className="resize-none"
              />
            </div>

            {/* Active toggle */}
            <div className="flex items-center justify-between rounded-lg border border-border p-3">
              <div>
                <p className="text-sm font-medium">Active</p>
                <p className="text-xs text-muted-foreground">Inactive ranges are ignored during scans but kept for reference.</p>
              </div>
              <Switch checked={form.isActive} onCheckedChange={v => setForm(f => ({ ...f, isActive: v }))} />
            </div>

            {editEntry?.isBuiltIn && (
              <div className="flex items-start gap-2 bg-blue-500/5 border border-blue-500/20 rounded-lg p-3 text-xs text-blue-300">
                <Info className="w-3.5 h-3.5 shrink-0 mt-0.5" />
                This is a built-in range. You can edit its label, description, and active state. The CIDR is editable but the original values were sourced from official provider documentation.
              </div>
            )}
          </div>

          <DialogFooter>
            <Button variant="outline" onClick={() => setShowDialog(false)}>Cancel</Button>
            <Button onClick={handleSave} disabled={saving || !cidrPreview || !form.label.trim()}>
              {saving && <Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" />}
              {editEntry ? "Save Changes" : "Add Range"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* ── Delete confirmation ───────────────────────────────────────────── */}
      <Dialog open={!!confirmDelete} onOpenChange={open => !open && setConfirmDelete(null)}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Trash2 className="w-4 h-4 text-destructive" /> Delete CDN Range
            </DialogTitle>
          </DialogHeader>
          {confirmDelete && (
            <div className="space-y-4 py-2">
              <p className="text-sm">
                Are you sure you want to delete <strong className="font-mono">{confirmDelete.cidr}</strong> ({confirmDelete.label})?
              </p>
              {confirmDelete.isBuiltIn && (
                <div className="flex items-start gap-2 bg-yellow-500/5 border border-yellow-500/20 rounded-lg p-3 text-xs text-yellow-300">
                  <AlertTriangle className="w-3.5 h-3.5 shrink-0 mt-0.5" />
                  This is a <strong>built-in range</strong> from official provider documentation. Deleting it means future scans will no longer apply the −20 parking deduction to domains resolving to this range. You can re-seed built-in ranges by restarting the API server with an empty table.
                </div>
              )}
              <p className="text-xs text-muted-foreground">
                This cannot be undone. The change takes effect on the next brand threat scan.
              </p>
            </div>
          )}
          <DialogFooter>
            <Button variant="outline" onClick={() => setConfirmDelete(null)}>Cancel</Button>
            <Button variant="destructive" onClick={() => confirmDelete && handleDelete(confirmDelete)} disabled={deleting !== null}>
              {deleting !== null && <Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" />}
              Delete
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
