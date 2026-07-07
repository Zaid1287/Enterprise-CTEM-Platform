import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  ChevronDown, ChevronRight, Pencil, Loader2, CheckCircle2, XCircle,
  Monitor, Smartphone, Globe,
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
import { useToast } from "@/hooks/use-toast";
import { cn } from "@/lib/utils";
import { getToken } from "@/lib/auth";
import { useAuth } from "@/hooks/useAuth";

/* ─── Types ─────────────────────────────────────────────────────────── */
interface FingerprintProfile {
  id: number; name: string;
  headers: Record<string, string>;
  isActive: boolean;
  createdAt: string; updatedAt: string;
}

/* ─── Default browser header sets for "Reset to Default" ─────────────── */
const DEFAULTS: Record<string, Record<string, string>> = {
  "Chrome 137 / Windows 10": {
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
  "Firefox 128 / Linux": {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
  },
  "Edge 127 / Windows 11": {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36 Edg/127.0.0.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Sec-CH-UA": '"Not_A Brand";v="8", "Chromium";v="127", "Microsoft Edge";v="127"',
    "Sec-CH-UA-Mobile": "?0",
    "Sec-CH-UA-Platform": '"Windows"',
  },
  "Safari 17 / macOS": {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
  },
  "Chrome 137 / Android Mobile": {
    "User-Agent": "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Mobile Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Sec-CH-UA-Mobile": "?1",
    "Sec-CH-UA-Platform": '"Android"',
  },
  "Safari / iOS 17": {
    "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
  },
};

/* ─── API ────────────────────────────────────────────────────────────── */
const BASE = () => import.meta.env.BASE_URL.replace(/\/$/, "");
const hdrs = () => ({ Authorization: `Bearer ${getToken()}`, "Content-Type": "application/json" });
async function api<T>(path: string, opts?: RequestInit): Promise<T> {
  const r = await fetch(`${BASE()}${path}`, { headers: hdrs(), ...opts });
  if (!r.ok) { const e = await r.json().catch(() => ({})); throw new Error((e as any).error ?? "Failed"); }
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

/* ─── Edit Dialog ─────────────────────────────────────────────────────── */
function EditDialog({ profile, onClose }: { profile: FingerprintProfile; onClose: () => void }) {
  const qc = useQueryClient();
  const { toast } = useToast();
  const [headers, setHeaders] = useState<Record<string, string>>(profile.headers ?? {});
  const [isActive, setIsActive] = useState(profile.isActive);

  const patchMut = useMutation({
    mutationFn: (body: object) =>
      api(`/api/scan-fingerprints/${profile.id}`, { method: "PATCH", body: JSON.stringify(body) }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["scan-fingerprints"] });
      toast({ title: "Profile updated" });
      onClose();
    },
    onError: (e: Error) => toast({ title: "Update failed", description: e.message, variant: "destructive" }),
  });

  const setHeader = (key: string, val: string) => setHeaders(h => ({ ...h, [key]: val }));

  const resetToDefault = () => {
    const d = DEFAULTS[profile.name];
    if (d) setHeaders(d);
    else toast({ title: "No default found for this profile name", variant: "destructive" });
  };

  const ALL_HEADER_KEYS = [
    "User-Agent", "Accept", "Accept-Language", "Accept-Encoding", "Connection",
    "Sec-CH-UA", "Sec-CH-UA-Mobile", "Sec-CH-UA-Platform",
    "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest", "Upgrade-Insecure-Requests", "DNT",
  ];

  return (
    <Dialog open onOpenChange={v => { if (!v) onClose(); }}>
      <DialogContent className="max-w-2xl max-h-[85vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>Edit: {profile.name}</DialogTitle>
        </DialogHeader>
        <div className="space-y-3 py-2">
          <div className="flex items-center gap-3">
            <Switch checked={isActive} onCheckedChange={setIsActive} id="active-toggle" />
            <Label htmlFor="active-toggle">Active (used in rotation)</Label>
          </div>
          <p className="text-xs text-muted-foreground">Edit header values below. Empty values omit the header.</p>
          <div className="space-y-2.5">
            {ALL_HEADER_KEYS.map(key => (
              <div key={key} className="grid grid-cols-[180px_1fr] gap-2 items-center">
                <Label className="text-xs font-mono">{key}</Label>
                <Input
                  className="text-xs font-mono h-8"
                  value={headers[key] ?? ""}
                  onChange={e => setHeader(key, e.target.value)}
                  placeholder="(omitted)"
                />
              </div>
            ))}
          </div>
        </div>
        <DialogFooter className="gap-2">
          <Button variant="outline" onClick={resetToDefault} className="mr-auto text-xs">
            Reset to Default
          </Button>
          <Button variant="ghost" onClick={onClose} disabled={patchMut.isPending}>Cancel</Button>
          <Button onClick={() => patchMut.mutate({ headers, isActive })} disabled={patchMut.isPending}>
            {patchMut.isPending && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
            Save Changes
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

  const { data: profiles = [], isLoading } = useQuery<FingerprintProfile[]>({
    queryKey: ["scan-fingerprints"],
    queryFn: () => api("/api/scan-fingerprints"),
  });

  return (
    <div className="p-6 space-y-6 max-w-screen-lg mx-auto">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Browser Fingerprint Profiles</h1>
        <p className="text-sm text-muted-foreground mt-0.5">
          System-defined HTTP header sets used to impersonate real browsers during scans
        </p>
      </div>

      <div className="rounded-xl border bg-card overflow-hidden">
        {isLoading ? (
          Array.from({ length: 6 }).map((_, i) => (
            <div key={i} className="px-4 py-3 border-b last:border-0 flex items-center gap-3">
              <Skeleton className="w-6 h-6 rounded" />
              <Skeleton className="h-4 w-48" />
              <Skeleton className="h-5 w-16 ml-auto" />
            </div>
          ))
        ) : profiles.map(profile => {
          const isOpen = expanded === profile.id;
          return (
            <div key={profile.id} className="border-b last:border-0">
              {/* Row */}
              <div
                className="px-4 py-3 flex items-center gap-3 cursor-pointer hover:bg-muted/30 transition-colors"
                onClick={() => setExpanded(isOpen ? null : profile.id)}
              >
                <ProfileIcon name={profile.name} />
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium">{profile.name}</p>
                  <p className="text-xs text-muted-foreground truncate">
                    {Object.keys(profile.headers ?? {}).length} headers defined
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  {profile.isActive
                    ? <Badge variant="outline" className="bg-green-500/10 text-green-600 border-green-500/25 gap-1 text-xs"><CheckCircle2 className="w-3 h-3" />Active</Badge>
                    : <Badge variant="outline" className="bg-muted text-muted-foreground gap-1 text-xs"><XCircle className="w-3 h-3" />Inactive</Badge>
                  }
                  {isSuperAdmin && (
                    <Button
                      variant="ghost" size="icon" className="w-7 h-7"
                      onClick={e => { e.stopPropagation(); setEditProfile(profile); }}
                      title="Edit profile"
                    >
                      <Pencil className="w-3.5 h-3.5" />
                    </Button>
                  )}
                  {isOpen ? <ChevronDown className="w-4 h-4 text-muted-foreground" /> : <ChevronRight className="w-4 h-4 text-muted-foreground" />}
                </div>
              </div>

              {/* Expanded: header table */}
              {isOpen && (
                <div className="px-4 pb-4 pt-1 bg-muted/20">
                  <div className="rounded-lg border overflow-hidden">
                    <table className="w-full text-xs">
                      <thead>
                        <tr className="border-b bg-muted/50">
                          <th className="px-3 py-2 text-left font-semibold text-muted-foreground">Header</th>
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
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>

      {editProfile && <EditDialog profile={editProfile} onClose={() => setEditProfile(null)} />}
    </div>
  );
}
