import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  ChevronDown, ChevronRight, Pencil, Loader2, CheckCircle2, XCircle,
  Monitor, Smartphone, Globe, Plus, Trash2, ShieldCheck,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter,
} from "@/components/ui/dialog";
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel,
  AlertDialogContent, AlertDialogDescription, AlertDialogFooter,
  AlertDialogHeader, AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { useToast } from "@/hooks/use-toast";
import { cn } from "@/lib/utils";
import { getToken } from "@/lib/auth";
import { useAuth } from "@/hooks/useAuth";

/* ─── Types ─────────────────────────────────────────────────────────── */
interface FingerprintProfile {
  id: number;
  name: string;
  headers: Record<string, string>;
  isActive: boolean;
  isBuiltIn: boolean;
  createdAt: string;
  updatedAt: string;
}

/* ─── All recognised HTTP header keys shown in the editor ────────────── */
const ALL_HEADER_KEYS = [
  "User-Agent",
  "Accept",
  "Accept-Language",
  "Accept-Encoding",
  "Connection",
  "Sec-CH-UA",
  "Sec-CH-UA-Mobile",
  "Sec-CH-UA-Platform",
  "Sec-Fetch-Site",
  "Sec-Fetch-Mode",
  "Sec-Fetch-Dest",
  "Upgrade-Insecure-Requests",
  "DNT",
];

/* ─── Default browser header sets for "Reset to Default" ─────────────── */
const DEFAULTS: Record<string, Record<string, string>> = {
  "Chrome 137 Windows": {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-CH-UA": '"Not_A Brand";v="8", "Chromium";v="137", "Google Chrome";v="137"',
    "Sec-CH-UA-Mobile": "?0",
    "Sec-CH-UA-Platform": '"Windows"',
  },
  "Firefox 128 Windows": {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
  },
};

/* ─── API helpers ─────────────────────────────────────────────────────── */
const BASE = () => import.meta.env.BASE_URL.replace(/\/$/, "");
const hdrs = () => ({ Authorization: `Bearer ${getToken()}`, "Content-Type": "application/json" });

async function api<T>(path: string, opts?: RequestInit): Promise<T> {
  const r = await fetch(`${BASE()}${path}`, { headers: hdrs(), ...opts });
  if (!r.ok) {
    const e = await r.json().catch(() => ({}));
    throw new Error((e as any).error ?? `Request failed (${r.status})`);
  }
  return r.json();
}

/* ─── Profile icon heuristic ─────────────────────────────────────────── */
function ProfileIcon({ name }: { name: string }) {
  const n = name.toLowerCase();
  if (n.includes("mobile") || n.includes("android") || n.includes("ios") || n.includes("iphone"))
    return <Smartphone className="w-4 h-4 text-blue-500" />;
  if (n.includes("safari") && n.includes("mac"))
    return <Globe className="w-4 h-4 text-sky-500" />;
  return <Monitor className="w-4 h-4 text-muted-foreground" />;
}

/* ─── Shared header editor ────────────────────────────────────────────── */
function HeaderEditor({
  headers,
  onChange,
  extraKeys = [],
}: {
  headers: Record<string, string>;
  onChange: (h: Record<string, string>) => void;
  extraKeys?: string[];
}) {
  const [newKey, setNewKey] = useState("");
  const [newVal, setNewVal] = useState("");

  const allKeys = [...new Set([...ALL_HEADER_KEYS, ...extraKeys, ...Object.keys(headers)])];

  const setHeader = (key: string, val: string) =>
    onChange({ ...headers, [key]: val });

  const addCustom = () => {
    const k = newKey.trim();
    if (!k) return;
    onChange({ ...headers, [k]: newVal.trim() });
    setNewKey("");
    setNewVal("");
  };

  return (
    <div className="space-y-2.5">
      {allKeys.map(key => (
        <div key={key} className="grid grid-cols-[180px_1fr] gap-2 items-center">
          <Label className="text-xs font-mono truncate" title={key}>{key}</Label>
          <Input
            className="text-xs font-mono h-8"
            value={headers[key] ?? ""}
            onChange={e => setHeader(key, e.target.value)}
            placeholder="(omitted)"
          />
        </div>
      ))}

      {/* Add a custom header not in the predefined list */}
      <div className="pt-2 border-t">
        <p className="text-xs text-muted-foreground mb-1.5">Add custom header</p>
        <div className="flex gap-2">
          <Input
            className="text-xs font-mono h-8 w-48"
            value={newKey}
            onChange={e => setNewKey(e.target.value)}
            placeholder="Header-Name"
            onKeyDown={e => { if (e.key === "Enter") addCustom(); }}
          />
          <Input
            className="text-xs font-mono h-8 flex-1"
            value={newVal}
            onChange={e => setNewVal(e.target.value)}
            placeholder="value"
            onKeyDown={e => { if (e.key === "Enter") addCustom(); }}
          />
          <Button type="button" size="sm" variant="outline" onClick={addCustom} className="h-8 px-3 text-xs">
            Add
          </Button>
        </div>
      </div>
    </div>
  );
}

/* ─── Edit Dialog (existing profile) ─────────────────────────────────── */
function EditDialog({ profile, onClose }: { profile: FingerprintProfile; onClose: () => void }) {
  const qc = useQueryClient();
  const { toast } = useToast();
  const [headers, setHeaders] = useState<Record<string, string>>(profile.headers ?? {});
  const [isActive, setIsActive] = useState(profile.isActive);
  const [name, setName] = useState(profile.name);

  const patchMut = useMutation({
    mutationFn: (body: object) =>
      api(`/api/scan-fingerprints/${profile.id}`, { method: "PATCH", body: JSON.stringify(body) }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["scan-fingerprints"] });
      toast({ title: "Profile updated", description: `"${name}" saved and active in rotation.` });
      onClose();
    },
    onError: (e: Error) => toast({ title: "Update failed", description: e.message, variant: "destructive" }),
  });

  const resetToDefault = () => {
    const d = DEFAULTS[profile.name];
    if (d) setHeaders(d);
    else toast({ title: "No default found for this profile name", variant: "destructive" });
  };

  const extraKeys = Object.keys(headers).filter(k => !ALL_HEADER_KEYS.includes(k));

  return (
    <Dialog open onOpenChange={v => { if (!v) onClose(); }}>
      <DialogContent className="max-w-2xl max-h-[85vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>Edit Profile</DialogTitle>
        </DialogHeader>
        <div className="space-y-4 py-2">
          {/* Name — built-in profiles cannot be renamed */}
          <div className="space-y-1">
            <Label className="text-xs">Profile Name</Label>
            {profile.isBuiltIn ? (
              <p className="text-sm font-mono bg-muted rounded px-3 py-1.5">{name}</p>
            ) : (
              <Input
                className="text-sm"
                value={name}
                onChange={e => setName(e.target.value)}
                placeholder="e.g. Chrome 120 / Tor Browser"
              />
            )}
          </div>

          <div className="flex items-center gap-3">
            <Switch checked={isActive} onCheckedChange={setIsActive} id="active-toggle" />
            <Label htmlFor="active-toggle" className="text-sm">Active (included in scan rotation)</Label>
          </div>

          <div>
            <p className="text-xs text-muted-foreground mb-2">
              Edit header values below. Leave a field empty to omit that header from requests.
            </p>
            <HeaderEditor headers={headers} onChange={setHeaders} extraKeys={extraKeys} />
          </div>
        </div>
        <DialogFooter className="gap-2">
          {profile.isBuiltIn && (
            <Button variant="outline" onClick={resetToDefault} className="mr-auto text-xs">
              Reset to Factory Default
            </Button>
          )}
          <Button variant="ghost" onClick={onClose} disabled={patchMut.isPending}>Cancel</Button>
          <Button
            onClick={() => patchMut.mutate({ name: profile.isBuiltIn ? undefined : name, headers, isActive })}
            disabled={patchMut.isPending}
          >
            {patchMut.isPending && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
            Save Changes
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

/* ─── Add Dialog (new custom profile) ────────────────────────────────── */
function AddDialog({ onClose }: { onClose: () => void }) {
  const qc = useQueryClient();
  const { toast } = useToast();
  const [name, setName] = useState("");
  const [isActive, setIsActive] = useState(true);
  const [headers, setHeaders] = useState<Record<string, string>>({
    "User-Agent": "",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
  });

  const createMut = useMutation({
    mutationFn: (body: object) =>
      api<FingerprintProfile>("/api/scan-fingerprints", { method: "POST", body: JSON.stringify(body) }),
    onSuccess: (created) => {
      qc.invalidateQueries({ queryKey: ["scan-fingerprints"] });
      toast({
        title: "Profile created",
        description: `"${created.name}" is now active in the scan rotation pool.`,
      });
      onClose();
    },
    onError: (e: Error) => toast({ title: "Create failed", description: e.message, variant: "destructive" }),
  });

  const handleSubmit = () => {
    const cleanHeaders = Object.fromEntries(
      Object.entries(headers).filter(([, v]) => v.trim().length > 0)
    );
    if (!name.trim()) {
      toast({ title: "Profile name is required", variant: "destructive" }); return;
    }
    if (!cleanHeaders["User-Agent"]) {
      toast({ title: "User-Agent header is required", description: "Every browser profile must have a User-Agent string.", variant: "destructive" }); return;
    }
    createMut.mutate({ name: name.trim(), headers: cleanHeaders, isActive });
  };

  return (
    <Dialog open onOpenChange={v => { if (!v) onClose(); }}>
      <DialogContent className="max-w-2xl max-h-[85vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>Add Browser Fingerprint Profile</DialogTitle>
        </DialogHeader>
        <div className="space-y-4 py-2">
          <div className="space-y-1">
            <Label className="text-xs">Profile Name <span className="text-destructive">*</span></Label>
            <Input
              className="text-sm"
              value={name}
              onChange={e => setName(e.target.value)}
              placeholder="e.g. Chrome 138 / Windows 11, Tor Browser 14, Custom Bot"
              autoFocus
            />
            <p className="text-xs text-muted-foreground">
              A unique, descriptive name. Appears in telemetry and A/B stats.
            </p>
          </div>

          <div className="flex items-center gap-3">
            <Switch checked={isActive} onCheckedChange={setIsActive} id="new-active-toggle" />
            <Label htmlFor="new-active-toggle" className="text-sm">
              Active immediately — include in scan rotation after saving
            </Label>
          </div>

          <div className="rounded-lg border border-amber-500/20 bg-amber-50/5 p-3 text-xs text-amber-600 dark:text-amber-400">
            <strong>How this works:</strong> This profile's HTTP headers will be injected into every
            orchestrated request made during scans. The scanner rotates through all active profiles
            using a UCB1 algorithm — profiles that achieve higher WAF-bypass success rates are
            selected more often. User-Agent is required; all other fields are optional.
          </div>

          <div>
            <p className="text-xs font-medium mb-2">HTTP Headers</p>
            <HeaderEditor headers={headers} onChange={setHeaders} />
          </div>
        </div>
        <DialogFooter className="gap-2">
          <Button variant="ghost" onClick={onClose} disabled={createMut.isPending}>Cancel</Button>
          <Button onClick={handleSubmit} disabled={createMut.isPending}>
            {createMut.isPending && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
            Create Profile
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

/* ─── Main Page ───────────────────────────────────────────────────────── */
export default function ScanFingerprintsPage() {
  const { user } = useAuth();
  const isSuperAdmin = user?.role === "super_admin";
  const [expanded, setExpanded] = useState<number | null>(null);
  const [editProfile, setEditProfile] = useState<FingerprintProfile | null>(null);
  const [showAdd, setShowAdd] = useState(false);
  const [deleteTarget, setDeleteTarget] = useState<FingerprintProfile | null>(null);

  const qc = useQueryClient();
  const { toast } = useToast();

  const { data: profiles = [], isLoading } = useQuery<FingerprintProfile[]>({
    queryKey: ["scan-fingerprints"],
    queryFn: () => api("/api/scan-fingerprints"),
  });

  const deleteMut = useMutation({
    mutationFn: (id: number) =>
      api(`/api/scan-fingerprints/${id}`, { method: "DELETE" }),
    onSuccess: (_, id) => {
      qc.invalidateQueries({ queryKey: ["scan-fingerprints"] });
      const name = deleteTarget?.name ?? `Profile #${id}`;
      toast({ title: "Profile deleted", description: `"${name}" removed from the rotation pool.` });
      setDeleteTarget(null);
    },
    onError: (e: Error) => {
      toast({ title: "Delete failed", description: e.message, variant: "destructive" });
      setDeleteTarget(null);
    },
  });

  const builtIn = profiles.filter(p => p.isBuiltIn);
  const custom  = profiles.filter(p => !p.isBuiltIn);

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Browser Fingerprint Profiles</h1>
          <p className="text-sm text-muted-foreground mt-0.5">
            HTTP header sets injected during scans to impersonate real browsers and evade WAF
            fingerprinting. The scanner picks profiles using UCB1 — higher-performing ones get more
            traffic.
          </p>
        </div>
        {isSuperAdmin && (
          <Button onClick={() => setShowAdd(true)} className="shrink-0 gap-2">
            <Plus className="w-4 h-4" />
            Add Profile
          </Button>
        )}
      </div>

      {/* Stats row */}
      {!isLoading && profiles.length > 0 && (
        <div className="grid grid-cols-3 gap-3 text-center">
          {[
            { label: "Total Profiles", value: profiles.length },
            { label: "Active in Rotation", value: profiles.filter(p => p.isActive).length },
            { label: "Custom (User-Created)", value: custom.length },
          ].map(s => (
            <div key={s.label} className="rounded-xl border bg-card p-3">
              <p className="text-2xl font-bold">{s.value}</p>
              <p className="text-xs text-muted-foreground mt-0.5">{s.label}</p>
            </div>
          ))}
        </div>
      )}

      {/* Built-in profiles */}
      <ProfileGroup
        title="Factory Profiles"
        subtitle="Pre-configured browser headers. Headers can be edited but profiles cannot be deleted."
        profiles={builtIn}
        isLoading={isLoading}
        expanded={expanded}
        onExpand={setExpanded}
        isSuperAdmin={isSuperAdmin}
        onEdit={setEditProfile}
        onDelete={null}
      />

      {/* Custom profiles */}
      {(custom.length > 0 || isLoading) && (
        <ProfileGroup
          title="Custom Profiles"
          subtitle="User-created profiles. Fully editable and deletable."
          profiles={custom}
          isLoading={false}
          expanded={expanded}
          onExpand={setExpanded}
          isSuperAdmin={isSuperAdmin}
          onEdit={setEditProfile}
          onDelete={isSuperAdmin ? setDeleteTarget : null}
        />
      )}

      {!isLoading && custom.length === 0 && isSuperAdmin && (
        <div className="rounded-xl border border-dashed bg-muted/20 p-8 text-center">
          <Monitor className="w-8 h-8 text-muted-foreground mx-auto mb-3" />
          <p className="text-sm font-medium">No custom profiles yet</p>
          <p className="text-xs text-muted-foreground mt-1 mb-4">
            Create a custom profile to add any browser, device, or bot identity to the rotation.
          </p>
          <Button variant="outline" size="sm" onClick={() => setShowAdd(true)} className="gap-2">
            <Plus className="w-4 h-4" />
            Add First Custom Profile
          </Button>
        </div>
      )}

      {/* Dialogs */}
      {showAdd && <AddDialog onClose={() => setShowAdd(false)} />}
      {editProfile && <EditDialog profile={editProfile} onClose={() => setEditProfile(null)} />}

      {/* Delete confirmation */}
      <AlertDialog open={!!deleteTarget} onOpenChange={v => { if (!v) setDeleteTarget(null); }}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete "{deleteTarget?.name}"?</AlertDialogTitle>
            <AlertDialogDescription>
              This profile will be permanently removed from the rotation pool. Any A/B performance
              stats collected for it will also be lost. This cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
              onClick={() => deleteTarget && deleteMut.mutate(deleteTarget.id)}
            >
              {deleteMut.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : "Delete"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}

/* ─── ProfileGroup ────────────────────────────────────────────────────── */
function ProfileGroup({
  title, subtitle, profiles, isLoading, expanded, onExpand, isSuperAdmin, onEdit, onDelete,
}: {
  title: string;
  subtitle: string;
  profiles: FingerprintProfile[];
  isLoading: boolean;
  expanded: number | null;
  onExpand: (id: number | null) => void;
  isSuperAdmin: boolean;
  onEdit: (p: FingerprintProfile) => void;
  onDelete: ((p: FingerprintProfile) => void) | null;
}) {
  return (
    <div className="space-y-1">
      <div className="flex items-baseline gap-2">
        <h2 className="text-sm font-semibold">{title}</h2>
        <span className="text-xs text-muted-foreground">— {subtitle}</span>
      </div>
      <div className="rounded-xl border bg-card overflow-hidden">
        {isLoading
          ? Array.from({ length: 3 }).map((_, i) => (
              <div key={i} className="px-4 py-3 border-b last:border-0 flex items-center gap-3">
                <Skeleton className="w-6 h-6 rounded" />
                <Skeleton className="h-4 w-48" />
                <Skeleton className="h-5 w-16 ml-auto" />
              </div>
            ))
          : profiles.map(profile => {
              const isOpen = expanded === profile.id;
              return (
                <div key={profile.id} className="border-b last:border-0">
                  {/* Row */}
                  <div
                    className="px-4 py-3 flex items-center gap-3 cursor-pointer hover:bg-muted/30 transition-colors"
                    onClick={() => onExpand(isOpen ? null : profile.id)}
                  >
                    <ProfileIcon name={profile.name} />
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <p className="text-sm font-medium truncate">{profile.name}</p>
                        {profile.isBuiltIn && (
                          <Badge variant="outline" className="text-[10px] gap-0.5 py-0 px-1.5 text-sky-600 border-sky-500/30 bg-sky-500/5 shrink-0">
                            <ShieldCheck className="w-2.5 h-2.5" />Factory
                          </Badge>
                        )}
                        {!profile.isBuiltIn && (
                          <Badge variant="outline" className="text-[10px] gap-0.5 py-0 px-1.5 text-violet-600 border-violet-500/30 bg-violet-500/5 shrink-0">
                            Custom
                          </Badge>
                        )}
                      </div>
                      <p className="text-xs text-muted-foreground truncate">
                        {Object.keys(profile.headers ?? {}).length} headers defined
                        {!profile.isBuiltIn && profile.createdAt && (
                          <> · added {new Date(profile.createdAt).toLocaleDateString()}</>
                        )}
                      </p>
                    </div>
                    <div className="flex items-center gap-1.5 shrink-0">
                      {profile.isActive
                        ? <Badge variant="outline" className="bg-green-500/10 text-green-600 border-green-500/25 gap-1 text-xs"><CheckCircle2 className="w-3 h-3" />Active</Badge>
                        : <Badge variant="outline" className="bg-muted text-muted-foreground gap-1 text-xs"><XCircle className="w-3 h-3" />Inactive</Badge>
                      }
                      {isSuperAdmin && (
                        <Button
                          variant="ghost" size="icon" className="w-7 h-7"
                          onClick={e => { e.stopPropagation(); onEdit(profile); }}
                          title="Edit profile"
                        >
                          <Pencil className="w-3.5 h-3.5" />
                        </Button>
                      )}
                      {onDelete && (
                        <Button
                          variant="ghost" size="icon"
                          className="w-7 h-7 text-destructive hover:text-destructive hover:bg-destructive/10"
                          onClick={e => { e.stopPropagation(); onDelete(profile); }}
                          title="Delete profile"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </Button>
                      )}
                      {isOpen
                        ? <ChevronDown className="w-4 h-4 text-muted-foreground" />
                        : <ChevronRight className="w-4 h-4 text-muted-foreground" />
                      }
                    </div>
                  </div>

                  {/* Expanded: header table */}
                  {isOpen && (
                    <div className="px-4 pb-4 pt-1 bg-muted/20">
                      <div className="rounded-lg border overflow-hidden">
                        <table className="w-full text-xs">
                          <thead>
                            <tr className="border-b bg-muted/50">
                              <th className="px-3 py-2 text-left font-semibold text-muted-foreground w-56">Header</th>
                              <th className="px-3 py-2 text-left font-semibold text-muted-foreground">Value</th>
                            </tr>
                          </thead>
                          <tbody>
                            {Object.entries(profile.headers ?? {}).map(([key, val]) => (
                              <tr key={key} className="border-b last:border-0 hover:bg-muted/30">
                                <td className="px-3 py-1.5 font-mono text-primary/80 whitespace-nowrap">{key}</td>
                                <td className="px-3 py-1.5 font-mono text-muted-foreground break-all">{val}</td>
                              </tr>
                            ))}
                            {Object.keys(profile.headers ?? {}).length === 0 && (
                              <tr>
                                <td colSpan={2} className="px-3 py-3 text-center text-muted-foreground">
                                  No headers defined
                                </td>
                              </tr>
                            )}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
      </div>
    </div>
  );
}
