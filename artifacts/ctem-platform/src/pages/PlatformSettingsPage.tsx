import { useState, useEffect } from "react";
import { useAuth } from "@/hooks/useAuth";
import { useLocation } from "wouter";
import {
  Key, Save, Eye, EyeOff, CheckCircle2, AlertTriangle, Mail, Bell,
  Search, Globe, ShieldAlert, Zap, Database, ExternalLink, Trash2,
  ChevronDown, ChevronUp, Wifi, WifiOff, RefreshCw,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";
import { apiFetch } from "@/lib/apiFetch";
import { useToast } from "@/hooks/use-toast";

interface PlatformSetting {
  key: string;
  label: string;
  description: string;
  category: string;
  hasValue: boolean;
  maskedValue: string;
}

const CATEGORY_META: Record<string, {
  label: string;
  icon: React.ElementType;
  color: string;
  bg: string;
  border: string;
  description: string;
  docsUrl?: string;
}> = {
  scanning: {
    label: "Scanning APIs",
    icon: Search,
    color: "text-emerald-400",
    bg: "bg-emerald-500/10",
    border: "border-emerald-500/20",
    description: "APIs used during active scanning phases (port recon, service detection)",
    docsUrl: "https://developer.shodan.io",
  },
  intelligence: {
    label: "Threat Intelligence",
    icon: ShieldAlert,
    color: "text-red-400",
    bg: "bg-red-500/10",
    border: "border-red-500/20",
    description: "CVE databases, vulnerability intelligence, KEV enrichment",
    docsUrl: "https://nvd.nist.gov/developers",
  },
  osint: {
    label: "OSINT & Intel",
    icon: Globe,
    color: "text-amber-400",
    bg: "bg-amber-500/10",
    border: "border-amber-500/20",
    description: "Passive intelligence sources — VirusTotal, AlienVault, URLScan",
    docsUrl: "https://developers.virustotal.com",
  },
  email: {
    label: "Email & SMTP",
    icon: Mail,
    color: "text-blue-400",
    bg: "bg-blue-500/10",
    border: "border-blue-500/20",
    description: "Transactional email for alerts, verifications, and reports via Resend",
    docsUrl: "https://resend.com/docs",
  },
  notifications: {
    label: "Notifications",
    icon: Bell,
    color: "text-purple-400",
    bg: "bg-purple-500/10",
    border: "border-purple-500/20",
    description: "Push notification channels — Slack, Telegram webhooks",
  },
  general: {
    label: "General",
    icon: Key,
    color: "text-muted-foreground",
    bg: "bg-muted/50",
    border: "border-border",
    description: "Miscellaneous platform configuration values",
  },
};

const BASE = import.meta.env.BASE_URL.replace(/\/$/, "");

export default function PlatformSettingsPage() {
  const { user } = useAuth();
  const [, navigate] = useLocation();
  const { toast } = useToast();

  const [settings, setSettings] = useState<PlatformSetting[]>([]);
  const [loading, setLoading] = useState(true);
  const [edits, setEdits] = useState<Record<string, string>>({});
  const [revealed, setRevealed] = useState<Record<string, string>>({});
  const [showKeys, setShowKeys] = useState<Set<string>>(new Set());
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set());

  useEffect(() => {
    if (user?.role !== "super_admin") { navigate("/dashboard"); return; }
    loadSettings();
  }, [user?.role]);

  const loadSettings = () => {
    setLoading(true);
    apiFetch<PlatformSetting[]>(`${BASE}/api/platform/settings`)
      .then(data => { setSettings(data); setLoading(false); })
      .catch(() => setLoading(false));
  };

  const handleReveal = async (key: string) => {
    if (revealed[key] !== undefined) {
      setShowKeys(prev => { const n = new Set(prev); n.has(key) ? n.delete(key) : n.add(key); return n; });
      return;
    }
    try {
      const { value } = await apiFetch<{ value: string }>(`${BASE}/api/platform/settings/raw/${key}`);
      setRevealed(prev => ({ ...prev, [key]: value }));
      setShowKeys(prev => { const n = new Set(prev); n.add(key); return n; });
    } catch {
      toast({ title: "Could not reveal key", variant: "destructive" });
    }
  };

  const handleSave = async () => {
    if (Object.keys(edits).length === 0) return;
    setSaving(true);
    try {
      await apiFetch(`${BASE}/api/platform/settings`, {
        method: "PUT",
        body: JSON.stringify(edits),
      });
      setSaved(true);
      setTimeout(() => setSaved(false), 2500);
      setEdits({});
      setRevealed({});
      setShowKeys(new Set());
      const data = await apiFetch<PlatformSetting[]>(`${BASE}/api/platform/settings`);
      setSettings(data);
      toast({ title: "Settings saved", description: `${Object.keys(edits).length} key(s) updated.` });
    } catch (e: any) {
      toast({ title: "Save failed", description: e.message, variant: "destructive" });
    } finally {
      setSaving(false);
    }
  };

  const handleClear = (key: string) => {
    setEdits(prev => ({ ...prev, [key]: "" }));
  };

  const handleDiscard = (key: string) => {
    setEdits(prev => { const n = { ...prev }; delete n[key]; return n; });
  };

  const toggleCollapse = (cat: string) =>
    setCollapsed(prev => { const n = new Set(prev); n.has(cat) ? n.delete(cat) : n.add(cat); return n; });

  const grouped = settings.reduce((acc, s) => {
    const cat = s.category ?? "general";
    if (!acc[cat]) acc[cat] = [];
    acc[cat].push(s);
    return acc;
  }, {} as Record<string, PlatformSetting[]>);

  const categoryOrder = ["scanning", "intelligence", "osint", "email", "notifications", "general"];
  const orderedGroups = categoryOrder.filter(c => grouped[c]);

  const totalSet = settings.filter(s => s.hasValue || edits[s.key] !== undefined).length;
  const totalKeys = settings.length;
  const pendingCount = Object.keys(edits).length;

  return (
    <div className="max-w-3xl space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-lg font-semibold">Platform Settings</h1>
          <p className="text-sm text-muted-foreground mt-0.5">
            Third-party API keys and service credentials — super admin only
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="ghost" size="sm" onClick={loadSettings} disabled={loading}>
            <RefreshCw className={cn("w-3.5 h-3.5", loading && "animate-spin")} />
          </Button>
          <Button
            size="sm"
            disabled={pendingCount === 0 || saving}
            onClick={handleSave}
            className={cn(
              "min-w-[120px] transition-all",
              saved && "bg-green-600 hover:bg-green-600 border-green-600",
            )}
          >
            {saved
              ? <><CheckCircle2 className="w-3.5 h-3.5 mr-1.5" /> Saved</>
              : saving
                ? <><RefreshCw className="w-3.5 h-3.5 mr-1.5 animate-spin" /> Saving…</>
                : <><Save className="w-3.5 h-3.5 mr-1.5" /> Save {pendingCount > 0 ? `(${pendingCount})` : "Changes"}</>
            }
          </Button>
        </div>
      </div>

      {/* Progress bar */}
      {!loading && totalKeys > 0 && (
        <div className="bg-card border border-border rounded-xl p-4 space-y-3">
          <div className="flex items-center justify-between text-xs">
            <span className="text-muted-foreground flex items-center gap-1.5">
              <Database className="w-3.5 h-3.5" /> Integration Coverage
            </span>
            <span className="font-semibold tabular-nums">
              <span className="text-foreground">{totalSet}</span>
              <span className="text-muted-foreground">/{totalKeys} configured</span>
            </span>
          </div>
          <div className="h-2 bg-muted rounded-full overflow-hidden">
            <div
              className="h-full rounded-full bg-gradient-to-r from-emerald-500 to-cyan-500 transition-all duration-700"
              style={{ width: `${Math.round((totalSet / totalKeys) * 100)}%` }}
            />
          </div>
          <div className="grid grid-cols-3 gap-2 pt-1">
            {orderedGroups.map(cat => {
              const meta = CATEGORY_META[cat] ?? CATEGORY_META.general;
              const grp = grouped[cat] ?? [];
              const set = grp.filter(s => s.hasValue || edits[s.key] !== undefined).length;
              return (
                <div key={cat} className={cn("rounded-lg p-2 border text-xs", meta.bg, meta.border)}>
                  <div className="flex items-center gap-1.5 mb-1">
                    <meta.icon className={cn("w-3 h-3", meta.color)} />
                    <span className={cn("font-medium", meta.color)}>{meta.label}</span>
                  </div>
                  <p className="text-muted-foreground">{set}/{grp.length} keys set</p>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Security notice */}
      <div className="flex items-start gap-3 bg-amber-500/8 border border-amber-500/25 rounded-xl px-4 py-3">
        <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
        <div className="text-xs text-amber-300/80 leading-relaxed">
          <span className="font-semibold text-amber-300">Security notice:</span>{" "}
          Credentials are stored encrypted in the platform database. Only super admins can view or edit them.
          Click the eye icon to reveal a stored value.
        </div>
      </div>

      {/* Loading skeletons */}
      {loading && (
        <div className="space-y-4">
          {[...Array(3)].map((_, i) => <Skeleton key={i} className="h-36 rounded-xl" />)}
        </div>
      )}

      {/* Category groups */}
      {!loading && orderedGroups.map(cat => {
        const meta = CATEGORY_META[cat] ?? CATEGORY_META.general;
        const Icon = meta.icon;
        const grp = grouped[cat] ?? [];
        const setCount = grp.filter(s => s.hasValue || edits[s.key] !== undefined).length;
        const pendingInGroup = grp.filter(s => edits[s.key] !== undefined).length;
        const isCollapsed = collapsed.has(cat);

        return (
          <div key={cat} className="bg-card border border-border rounded-xl overflow-hidden">
            {/* Section header */}
            <button
              className="w-full flex items-center justify-between px-5 py-4 hover:bg-accent/20 transition-colors"
              onClick={() => toggleCollapse(cat)}
            >
              <div className="flex items-center gap-3">
                <div className={cn("w-8 h-8 rounded-lg flex items-center justify-center border", meta.bg, meta.border)}>
                  <Icon className={cn("w-4 h-4", meta.color)} />
                </div>
                <div className="text-left">
                  <div className="flex items-center gap-2">
                    <h2 className="text-sm font-semibold">{meta.label}</h2>
                    {pendingInGroup > 0 && (
                      <span className="text-[9px] font-bold uppercase px-1.5 py-0.5 rounded bg-amber-500/15 text-amber-400 border border-amber-500/30">
                        {pendingInGroup} unsaved
                      </span>
                    )}
                  </div>
                  <p className="text-xs text-muted-foreground">{meta.description}</p>
                </div>
              </div>
              <div className="flex items-center gap-3">
                <div className="flex items-center gap-1.5 text-xs">
                  {setCount === grp.length
                    ? <span className="flex items-center gap-1 text-green-400"><CheckCircle2 className="w-3.5 h-3.5" /> All set</span>
                    : <span className="text-muted-foreground">{setCount}/{grp.length} configured</span>}
                </div>
                {meta.docsUrl && (
                  <a
                    href={meta.docsUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    onClick={e => e.stopPropagation()}
                    className="text-muted-foreground hover:text-foreground transition-colors"
                    title="Documentation"
                  >
                    <ExternalLink className="w-3.5 h-3.5" />
                  </a>
                )}
                {isCollapsed ? <ChevronDown className="w-4 h-4 text-muted-foreground" /> : <ChevronUp className="w-4 h-4 text-muted-foreground" />}
              </div>
            </button>

            {/* Settings list */}
            {!isCollapsed && (
              <div className="divide-y divide-border/50 border-t border-border/50">
                {grp.map(setting => {
                  const editVal = edits[setting.key];
                  const isEdited = editVal !== undefined;
                  const isRevealed = showKeys.has(setting.key);
                  const revealedVal = revealed[setting.key];
                  const hasValue = setting.hasValue && !isEdited;

                  return (
                    <div key={setting.key} className={cn("px-5 py-4 space-y-2", isEdited && "bg-amber-500/3")}>
                      <div className="flex items-start justify-between gap-4">
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 flex-wrap">
                            <label className="text-xs font-semibold text-foreground">{setting.label}</label>
                            {hasValue && !isEdited && (
                              <span className="inline-flex items-center gap-0.5 text-[9px] px-1.5 py-0.5 rounded-full bg-green-500/12 text-green-400 border border-green-500/25 font-bold uppercase tracking-wide">
                                <Wifi className="w-2.5 h-2.5" /> Connected
                              </span>
                            )}
                            {!hasValue && !isEdited && (
                              <span className="inline-flex items-center gap-0.5 text-[9px] px-1.5 py-0.5 rounded-full bg-muted text-muted-foreground border border-border font-bold uppercase tracking-wide">
                                <WifiOff className="w-2.5 h-2.5" /> Not Set
                              </span>
                            )}
                            {isEdited && (
                              <span className="text-[9px] px-1.5 py-0.5 rounded-full bg-amber-500/15 text-amber-400 border border-amber-500/30 font-bold uppercase tracking-wide">
                                Unsaved
                              </span>
                            )}
                          </div>
                          {setting.description && (
                            <p className="text-[11px] text-muted-foreground mt-0.5 leading-relaxed">{setting.description}</p>
                          )}
                        </div>
                        <div className="flex items-center gap-1 shrink-0">
                          {setting.hasValue && (
                            <button
                              onClick={() => handleReveal(setting.key)}
                              className="flex items-center gap-1 text-[10px] text-muted-foreground hover:text-foreground transition-colors px-2 py-1 rounded hover:bg-accent"
                            >
                              {isRevealed ? <EyeOff className="w-3 h-3" /> : <Eye className="w-3 h-3" />}
                              {isRevealed ? "Hide" : "Reveal"}
                            </button>
                          )}
                          {isEdited && (
                            <button
                              onClick={() => handleDiscard(setting.key)}
                              className="text-[10px] text-muted-foreground hover:text-foreground transition-colors px-2 py-1 rounded hover:bg-accent"
                            >
                              Discard
                            </button>
                          )}
                        </div>
                      </div>

                      <div className="relative flex gap-2">
                        <div className="relative flex-1">
                          <Input
                            type={isRevealed ? "text" : "password"}
                            className={cn(
                              "h-9 text-sm font-mono transition-colors",
                              isEdited && "border-amber-500/50 bg-amber-500/3",
                              hasValue && !isEdited && "border-green-500/30",
                            )}
                            placeholder={
                              hasValue && !isEdited && !isRevealed
                                ? setting.maskedValue || "••••••••••••••••"
                                : `Paste ${setting.label}…`
                            }
                            value={
                              isEdited ? editVal
                              : isRevealed ? (revealedVal ?? "")
                              : ""
                            }
                            onChange={e => setEdits(prev => ({ ...prev, [setting.key]: e.target.value }))}
                          />
                        </div>
                        {setting.hasValue && !isEdited && (
                          <Button
                            variant="ghost"
                            size="sm"
                            className="h-9 text-destructive hover:text-destructive hover:bg-destructive/10 shrink-0 px-2.5"
                            onClick={() => handleClear(setting.key)}
                            title="Clear this key"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </Button>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        );
      })}

      {/* Bottom save bar (sticky) — appears when there are unsaved edits */}
      {pendingCount > 0 && (
        <div className="sticky bottom-4 flex items-center justify-between bg-card border border-border rounded-xl px-4 py-3 shadow-xl shadow-black/30">
          <div className="flex items-center gap-2 text-sm">
            <Zap className="w-4 h-4 text-amber-400" />
            <span className="font-medium">{pendingCount} unsaved change{pendingCount !== 1 ? "s" : ""}</span>
          </div>
          <div className="flex gap-2">
            <Button variant="ghost" size="sm" onClick={() => setEdits({})}>Discard all</Button>
            <Button size="sm" onClick={handleSave} disabled={saving}>
              {saving ? "Saving…" : "Save All"}
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}
