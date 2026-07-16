import { useState, useEffect } from "react";
import { useAuth } from "@/hooks/useAuth";
import { useLocation } from "wouter";
import {
  Key, Save, Eye, EyeOff, CheckCircle2, AlertTriangle, Mail, Bell,
  Search, Globe, ShieldAlert, Database, ExternalLink, Trash2,
  Wifi, WifiOff, RefreshCw, ChevronRight, Loader2, FlaskConical, Brain, Activity,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
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
  comingSoon?: boolean;
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
  infrastructure: {
    label: "Infrastructure",
    icon: Database,
    color: "text-violet-400",
    bg: "bg-violet-500/10",
    border: "border-violet-500/20",
    description: "Core infrastructure configuration — Redis URL for BullMQ durable scan queuing, crash recovery, and distributed worker support.",
  },
  scanning: {
    label: "Scanning APIs",
    icon: Search,
    color: "text-emerald-400",
    bg: "bg-emerald-500/10",
    border: "border-emerald-500/20",
    description: "APIs used during active scanning — port recon, service detection",
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
    description: "Passive intelligence — VirusTotal, AlienVault, URLScan",
    docsUrl: "https://developers.virustotal.com",
  },
  email: {
    label: "Email & SMTP",
    icon: Mail,
    color: "text-blue-400",
    bg: "bg-blue-500/10",
    border: "border-blue-500/20",
    description: "Transactional email for alerts, verifications, and reports",
    docsUrl: "https://resend.com/docs",
  },
  notifications: {
    label: "Notifications",
    icon: Bell,
    color: "text-purple-400",
    bg: "bg-purple-500/10",
    border: "border-purple-500/20",
    description: "Push notification channels — Slack, Discord, Telegram",
  },
  brand_threat: {
    label: "Brand Threat Intelligence",
    icon: ShieldAlert,
    color: "text-rose-400",
    bg: "bg-rose-500/10",
    border: "border-rose-500/20",
    description: "HIBP, Google Safe Browsing, WhoisXML — powers the advanced brand threat module",
    docsUrl: "https://haveibeenpwned.com/API/v3",
  },
  brand_intelligence: {
    label: "Brand Intelligence",
    icon: Search,
    color: "text-violet-400",
    bg: "bg-violet-500/10",
    border: "border-violet-500/20",
    description: "Meta Ads Library, YouTube, and social platform monitoring for brand impersonation and malicious ad campaigns",
    docsUrl: "https://developers.facebook.com/docs/marketing-api/reference/ads-archive/",
  },
  billing: {
    label: "Billing & Payments",
    icon: Key,
    color: "text-emerald-400",
    bg: "bg-emerald-500/10",
    border: "border-emerald-500/20",
    description: "Stripe API keys for subscription billing, checkout, and the customer portal",
    docsUrl: "https://dashboard.stripe.com/apikeys",
  },
  waf_bypass: {
    label: "WAF Bypass & CAPTCHA",
    icon: ShieldAlert,
    color: "text-orange-400",
    bg: "bg-orange-500/10",
    border: "border-orange-500/20",
    description: "Automated CAPTCHA solving (2captcha / CapMonster) for reCAPTCHA, hCaptcha, and Cloudflare Turnstile challenges encountered during scans",
    docsUrl: "https://2captcha.com",
  },
  general: {
    label: "General",
    icon: Key,
    color: "text-muted-foreground",
    bg: "bg-muted/50",
    border: "border-border",
    description: "Miscellaneous platform configuration values",
  },
  shadow_it: {
    label: "Shadow IT / IdP Credentials",
    icon: EyeOff,
    color: "text-purple-400",
    bg: "bg-purple-500/10",
    border: "border-purple-500/20",
    description: "API credentials for Identity Provider integrations — Google Workspace Service Account, Microsoft Azure Client Secret, and Okta API Token. Required by the Shadow IT SaaS & OAuth Discovery module to enumerate OAuth apps and user attributions.",
    docsUrl: "https://workspace.google.com/products/admin/",
  },
};

const CATEGORY_ORDER = ["infrastructure", "billing", "scanning", "waf_bypass", "intelligence", "osint", "brand_threat", "brand_intelligence", "shadow_it", "email", "notifications", "general"];
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
  const [testResults, setTestResults] = useState<Record<string, { ok: boolean; message: string }>>({});
  const [testingKey, setTestingKey] = useState<string | null>(null);
  const [restartingWorkers, setRestartingWorkers] = useState(false);
  const [redisStatus, setRedisStatus] = useState<{ redisConfigured: boolean; redisConnected: boolean; bullmqActive: boolean } | null>(null);
  const [aiStatus, setAiStatus] = useState<{ llmEnabled: boolean; provider: string | null; model: string; providersCount: number } | null>(null);

  const TESTABLE_KEYS = new Set(["shodan_api_key", "virustotal_api_key", "nvd_api_key", "censys_api_id", "redis_url"]);

  const handleTestKey = async (key: string) => {
    setTestingKey(key);
    try {
      let res: { ok: boolean; message: string };
      if (key === "redis_url" && edits[key] !== undefined) {
        res = await apiFetch<{ ok: boolean; message: string }>(`${BASE}/api/admin/redis/test`, {
          method: "POST",
          body: JSON.stringify({ url: edits[key] }),
        });
      } else {
        res = await apiFetch<{ ok: boolean; message: string }>(`${BASE}/api/platform/settings/test-key`, {
          method: "POST",
          body: JSON.stringify({ key }),
        });
      }
      setTestResults(prev => ({ ...prev, [key]: res }));
    } catch (e: any) {
      setTestResults(prev => ({ ...prev, [key]: { ok: false, message: e.message ?? "Test failed" } }));
    } finally {
      setTestingKey(null);
    }
  };

  const loadRedisStatus = () => {
    apiFetch<{ redisConfigured: boolean; redisConnected: boolean; bullmqActive: boolean }>(`${BASE}/api/platform/workers/status`)
      .then(data => setRedisStatus(data))
      .catch(() => {});
  };

  const loadAiStatus = () => {
    apiFetch<{ llmEnabled: boolean; provider: string | null; model: string; providersCount: number }>(`${BASE}/api/ai/status`)
      .then(data => setAiStatus(data))
      .catch(() => {});
  };

  const [selectedCat, setSelectedCat] = useState("scanning");

  useEffect(() => {
    if (user?.role !== "super_admin") { navigate("/dashboard"); return; }
    loadSettings();
    loadRedisStatus();
    loadAiStatus();
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

  const handleRestartWorkers = async () => {
    setRestartingWorkers(true);
    try {
      const res = await apiFetch<{ ok: boolean; message: string }>(`${BASE}/api/platform/workers/restart`, { method: "POST" });
      toast({ title: res.ok ? "Workers restarted" : "Restart failed", description: res.message, variant: res.ok ? "default" : "destructive" });
      if (res.ok) loadRedisStatus();
    } catch (e: any) {
      toast({ title: "Restart failed", description: e?.message ?? "Unknown error", variant: "destructive" });
    } finally {
      setRestartingWorkers(false);
    }
  };

  const handleSave = async () => {
    if (Object.keys(edits).length === 0) return;
    const pendingEditsSnapshot = { ...edits };
    setSaving(true);
    try {
      const result = await apiFetch<{ ok: boolean; workersRestarted?: boolean }>(`${BASE}/api/platform/settings`, {
        method: "PUT",
        body: JSON.stringify(pendingEditsSnapshot),
      });
      setSaved(true);
      setTimeout(() => setSaved(false), 2500);
      setEdits({});
      setRevealed({});
      setShowKeys(new Set());
      const data = await apiFetch<PlatformSetting[]>(`${BASE}/api/platform/settings`);
      setSettings(data);
      if (result.workersRestarted) {
        loadRedisStatus();
        toast({ title: "Settings saved — Redis workers restarted", description: "BullMQ workers are now using the new Redis URL." });
      } else {
        toast({ title: "Settings saved", description: `${Object.keys(pendingEditsSnapshot).length} key(s) updated.` });
      }
    } catch (e: any) {
      toast({ title: "Save failed", description: e.message, variant: "destructive" });
    } finally {
      setSaving(false);
    }
  };

  const grouped = settings.reduce((acc, s) => {
    const cat = s.category ?? "general";
    if (!acc[cat]) acc[cat] = [];
    acc[cat].push(s);
    return acc;
  }, {} as Record<string, PlatformSetting[]>);

  const orderedGroups = CATEGORY_ORDER.filter(c => grouped[c]);
  const totalSet = settings.filter(s => s.hasValue || edits[s.key] !== undefined).length;
  const totalKeys = settings.length;
  const pendingCount = Object.keys(edits).length;
  const coveragePct = totalKeys > 0 ? Math.round((totalSet / totalKeys) * 100) : 0;

  const currentGroup = grouped[selectedCat] ?? [];
  const currentMeta = CATEGORY_META[selectedCat] ?? CATEGORY_META.general;

  return (
    <div className="space-y-5">
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
              "min-w-[130px] transition-all",
              saved && "bg-green-600 hover:bg-green-600 border-green-600",
            )}
          >
            {saved
              ? <><CheckCircle2 className="w-3.5 h-3.5 mr-1.5" /> Saved</>
              : saving
                ? <><RefreshCw className="w-3.5 h-3.5 mr-1.5 animate-spin" /> Saving…</>
                : <><Save className="w-3.5 h-3.5 mr-1.5" /> Save{pendingCount > 0 ? ` (${pendingCount})` : " Changes"}</>
            }
          </Button>
        </div>
      </div>

      {/* Security notice */}
      <div className="flex items-start gap-3 bg-amber-500/8 border border-amber-500/25 rounded-xl px-4 py-3">
        <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
        <p className="text-xs text-amber-300/80 leading-relaxed">
          <span className="font-semibold text-amber-300">Security notice:</span>{" "}
          Credentials are stored encrypted in the platform database. Only super admins can view or edit them.
          Click the eye icon to reveal a stored value.
        </p>
      </div>

      {/* AI Copilot status */}
      {aiStatus !== null && (
        <div className={cn(
          "flex items-center justify-between gap-4 rounded-xl border px-4 py-3",
          aiStatus.llmEnabled
            ? "bg-emerald-500/8 border-emerald-500/25"
            : "bg-muted/30 border-border/50",
        )}>
          <div className="flex items-center gap-3">
            <div className={cn(
              "w-8 h-8 rounded-lg flex items-center justify-center border",
              aiStatus.llmEnabled ? "bg-emerald-500/15 border-emerald-500/30" : "bg-muted/50 border-border",
            )}>
              <Brain className={cn("w-4 h-4", aiStatus.llmEnabled ? "text-emerald-400" : "text-muted-foreground")} />
            </div>
            <div>
              <p className="text-sm font-medium">AI Copilot</p>
              {aiStatus.llmEnabled ? (
                <p className="text-[11px] text-emerald-400/80">
                  Active · {aiStatus.provider ?? "unknown"} · {aiStatus.model}
                  {aiStatus.providersCount > 1 && <span className="text-muted-foreground ml-1">+{aiStatus.providersCount - 1} more</span>}
                </p>
              ) : (
                <p className="text-[11px] text-muted-foreground">No API key configured — running in template mode</p>
              )}
            </div>
          </div>
          <div className="flex items-center gap-2">
            {aiStatus.llmEnabled
              ? <CheckCircle2 className="w-4 h-4 text-emerald-400" />
              : <AlertTriangle className="w-4 h-4 text-muted-foreground/50" />}
            <a href="/settings/account" className="text-[11px] text-primary/70 hover:text-primary underline underline-offset-2 whitespace-nowrap flex items-center gap-1">
              <Activity className="w-3 h-3" /> Configure per-user keys
            </a>
          </div>
        </div>
      )}

      {loading ? (
        <div className="grid grid-cols-[260px_1fr] gap-5">
          <div className="space-y-2">
            {[...Array(6)].map((_, i) => <Skeleton key={i} className="h-14 rounded-xl" />)}
          </div>
          <div className="space-y-3">
            {[...Array(4)].map((_, i) => <Skeleton key={i} className="h-24 rounded-xl" />)}
          </div>
        </div>
      ) : (
        <div className="grid grid-cols-[260px_1fr] gap-5 items-start">
          {/* Left sidebar — category navigation */}
          <div className="space-y-2 sticky top-4">
            {/* Coverage summary card */}
            <div className="bg-card border border-border rounded-xl p-4 space-y-3 mb-4">
              <div className="flex items-center justify-between text-xs">
                <span className="text-muted-foreground flex items-center gap-1.5">
                  <Database className="w-3.5 h-3.5" /> Integration Coverage
                </span>
                <span className="font-semibold tabular-nums">
                  <span className="text-foreground">{totalSet}</span>
                  <span className="text-muted-foreground">/{totalKeys}</span>
                </span>
              </div>
              <div className="h-2 bg-muted rounded-full overflow-hidden">
                <div
                  className="h-full rounded-full bg-gradient-to-r from-emerald-500 to-cyan-500 transition-all duration-700"
                  style={{ width: `${coveragePct}%` }}
                />
              </div>
              <p className="text-[11px] text-muted-foreground text-center">{coveragePct}% of API keys configured</p>
            </div>

            {/* Category nav items */}
            {orderedGroups.map(cat => {
              const meta = CATEGORY_META[cat] ?? CATEGORY_META.general;
              const Icon = meta.icon;
              const grp = grouped[cat] ?? [];
              const setCount = grp.filter(s => s.hasValue || edits[s.key] !== undefined).length;
              const pendingInGroup = grp.filter(s => edits[s.key] !== undefined).length;
              const isSelected = selectedCat === cat;
              const allSet = setCount === grp.length;

              return (
                <button
                  key={cat}
                  onClick={() => setSelectedCat(cat)}
                  className={cn(
                    "w-full flex items-center gap-3 px-3 py-2.5 rounded-xl text-left transition-all border",
                    isSelected
                      ? "border-primary/40 bg-primary/5 text-foreground"
                      : "border-transparent hover:border-border hover:bg-accent/30 text-muted-foreground",
                  )}
                >
                  <div className={cn("w-8 h-8 rounded-lg flex items-center justify-center shrink-0 border", meta.bg, meta.border)}>
                    <Icon className={cn("w-4 h-4", meta.color)} />
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-1.5">
                      <p className="text-sm font-medium truncate">{meta.label}</p>
                      {pendingInGroup > 0 && (
                        <span className="text-[9px] font-bold px-1.5 py-0.5 rounded bg-amber-500/15 text-amber-400 border border-amber-500/30 shrink-0">
                          {pendingInGroup}
                        </span>
                      )}
                    </div>
                    <p className="text-[11px] text-muted-foreground/70">
                      {allSet
                        ? <span className="text-green-400 flex items-center gap-1"><CheckCircle2 className="w-3 h-3" /> All set</span>
                        : `${setCount}/${grp.length} configured`}
                    </p>
                  </div>
                  {isSelected && <ChevronRight className="w-3.5 h-3.5 text-muted-foreground shrink-0" />}
                </button>
              );
            })}
          </div>

          {/* Right panel — settings for selected category */}
          <div className="bg-card border border-border rounded-xl overflow-hidden">
            {/* Panel header */}
            <div className={cn("flex items-center justify-between px-6 py-4 border-b border-border", currentMeta.bg)}>
              <div className="flex items-center gap-3">
                <div className={cn("w-9 h-9 rounded-lg flex items-center justify-center border", currentMeta.bg, currentMeta.border)}>
                  <currentMeta.icon className={cn("w-4.5 h-4.5", currentMeta.color)} />
                </div>
                <div>
                  <h2 className="text-sm font-semibold">{currentMeta.label}</h2>
                  <p className="text-xs text-muted-foreground">{currentMeta.description}</p>
                </div>
              </div>
              {currentMeta.docsUrl && (
                <a
                  href={currentMeta.docsUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground transition-colors"
                >
                  <ExternalLink className="w-3.5 h-3.5" /> Docs
                </a>
              )}
            </div>

            {/* Keys list */}
            <div className="divide-y divide-border/50">
              {currentGroup.length === 0 && (
                <div className="px-6 py-12 text-center text-sm text-muted-foreground">
                  No settings in this category.
                </div>
              )}
              {currentGroup.map(setting => {
                const editVal = edits[setting.key];
                const isEdited = editVal !== undefined;
                const isRevealed = showKeys.has(setting.key);
                const revealedVal = revealed[setting.key];
                const hasValue = setting.hasValue && !isEdited;
                const isComingSoon = setting.comingSoon === true;

                return (
                  <div key={setting.key} className={cn("px-6 py-5", isEdited && "bg-amber-500/3", isComingSoon && "opacity-60")}>
                    <div className="flex items-start justify-between gap-6">
                      {/* Label + description */}
                      <div className="w-72 shrink-0">
                        <div className="flex items-center gap-2 flex-wrap mb-1">
                          <p className="text-sm font-semibold">{setting.label}</p>
                          {isComingSoon && (
                            <span className="inline-flex items-center gap-0.5 text-[9px] px-1.5 py-0.5 rounded-full bg-violet-500/10 text-violet-400 border border-violet-500/25 font-bold uppercase tracking-wide">
                              Coming Soon
                            </span>
                          )}
                          {!isComingSoon && hasValue && !isEdited && (
                            <span className="inline-flex items-center gap-0.5 text-[9px] px-1.5 py-0.5 rounded-full bg-green-500/12 text-green-400 border border-green-500/25 font-bold uppercase tracking-wide">
                              <Wifi className="w-2.5 h-2.5" /> Connected
                            </span>
                          )}
                          {!isComingSoon && !hasValue && !isEdited && (
                            <span className="inline-flex items-center gap-0.5 text-[9px] px-1.5 py-0.5 rounded-full bg-muted text-muted-foreground border border-border font-bold uppercase tracking-wide">
                              <WifiOff className="w-2.5 h-2.5" /> Not Set
                            </span>
                          )}
                          {!isComingSoon && isEdited && (
                            <span className="text-[9px] px-1.5 py-0.5 rounded-full bg-amber-500/15 text-amber-400 border border-amber-500/30 font-bold uppercase tracking-wide">
                              Unsaved
                            </span>
                          )}
                        </div>
                        {setting.description && (
                          <p className="text-[11px] text-muted-foreground leading-relaxed">{setting.description}</p>
                        )}
                        <p className="text-[10px] font-mono text-muted-foreground/60 mt-1.5">{setting.key}</p>
                      </div>

                      {/* Input + actions */}
                      <div className="flex-1 min-w-0 space-y-2">
                        <div className="flex gap-2">
                          <div className="relative flex-1">
                            <Input
                              type={isRevealed ? "text" : "password"}
                              className={cn(
                                "h-9 text-sm font-mono pr-24 transition-colors",
                                isEdited && "border-amber-500/50 bg-amber-500/3",
                                hasValue && !isEdited && "border-green-500/30",
                                isComingSoon && !isEdited && "opacity-70",
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
                          <div className="flex items-center gap-1 shrink-0">
                            {setting.hasValue && (
                              <button
                                onClick={() => handleReveal(setting.key)}
                                className="flex items-center gap-1 text-[10px] text-muted-foreground hover:text-foreground transition-colors px-2.5 py-2 rounded-lg hover:bg-accent border border-border h-9"
                              >
                                {isRevealed ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                                <span className="hidden sm:inline">{isRevealed ? "Hide" : "Reveal"}</span>
                              </button>
                            )}
                            {((setting.hasValue && !isEdited) || (setting.key === "redis_url" && isEdited && edits[setting.key])) && TESTABLE_KEYS.has(setting.key) && (
                              <button
                                onClick={() => handleTestKey(setting.key)}
                                disabled={testingKey === setting.key}
                                className="flex items-center gap-1 text-[10px] text-blue-400 hover:text-blue-300 transition-colors px-2.5 py-2 rounded-lg hover:bg-blue-500/10 border border-border h-9 disabled:opacity-50"
                                title={setting.key === "redis_url" && isEdited ? "Test this URL (without saving)" : "Test connection"}
                              >
                                {testingKey === setting.key ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <FlaskConical className="w-3.5 h-3.5" />}
                                <span className="hidden sm:inline">Test</span>
                              </button>
                            )}
                            {setting.hasValue && !isEdited && (
                              <button
                                onClick={() => setEdits(prev => ({ ...prev, [setting.key]: "" }))}
                                className="flex items-center gap-1 text-[10px] text-destructive hover:text-destructive/80 transition-colors px-2.5 py-2 rounded-lg hover:bg-destructive/10 border border-border h-9"
                                title="Clear this key"
                              >
                                <Trash2 className="w-3.5 h-3.5" />
                              </button>
                            )}
                            {isEdited && (
                              <button
                                onClick={() => setEdits(prev => { const n = { ...prev }; delete n[setting.key]; return n; })}
                                className="text-[10px] text-muted-foreground hover:text-foreground transition-colors px-2.5 py-2 rounded-lg hover:bg-accent border border-border h-9 whitespace-nowrap"
                              >
                                Discard
                              </button>
                            )}
                          </div>
                        </div>
                        {testResults[setting.key] && !isEdited && (
                          <p className={cn("text-[10px] mt-1 flex items-center gap-1", testResults[setting.key].ok ? "text-green-400" : "text-red-400")}>
                            {testResults[setting.key].ok ? <CheckCircle2 className="w-3 h-3" /> : <AlertTriangle className="w-3 h-3" />}
                            {testResults[setting.key].message}
                          </p>
                        )}
                        {setting.key === "redis_url" && !isEdited && (
                          <div className="flex items-center gap-2 flex-wrap mt-1">
                            {redisStatus && (
                              <span className={cn(
                                "inline-flex items-center gap-1 text-[10px] px-2 py-0.5 rounded-full border font-semibold",
                                redisStatus.redisConnected
                                  ? "bg-green-500/10 text-green-400 border-green-500/25"
                                  : redisStatus.redisConfigured
                                    ? "bg-amber-500/10 text-amber-400 border-amber-500/25"
                                    : "bg-muted text-muted-foreground border-border",
                              )}>
                                {redisStatus.redisConnected
                                  ? <><Wifi className="w-2.5 h-2.5" /> Live — BullMQ active</>
                                  : redisStatus.redisConfigured
                                    ? <><WifiOff className="w-2.5 h-2.5" /> Configured but not connected</>
                                    : <><WifiOff className="w-2.5 h-2.5" /> Not connected</>
                                }
                              </span>
                            )}
                            {setting.hasValue && (
                              <button
                                onClick={handleRestartWorkers}
                                disabled={restartingWorkers}
                                className="flex items-center gap-1 text-[10px] text-violet-400 hover:text-violet-300 transition-colors px-2 py-0.5 rounded-md hover:bg-violet-500/10 border border-violet-500/20 disabled:opacity-50"
                              >
                                {restartingWorkers ? <Loader2 className="w-3 h-3 animate-spin" /> : <RefreshCw className="w-3 h-3" />}
                                Apply &amp; Restart Workers
                              </button>
                            )}
                          </div>
                        )}
                        {isComingSoon && (
                          <p className="text-[10px] text-violet-400/70 mt-1">
                            {setting.key === "twitter_x_bearer_token"
                              ? "Requires a Twitter/X paid developer account (Basic tier or above). Save your token now — scanning activates once the paid tier is enabled."
                              : setting.key === "instagram_graph_api_token"
                              ? "Requires Facebook for Business App Review approval before the Graph API can monitor brand content. Save your token now — scanning activates once approved."
                              : setting.key === "tiktok_research_api_token"
                              ? "Requires TikTok Research API developer program approval. Save your token now — scanning activates once your application is approved."
                              : "Scanning support coming soon — save your token now so it activates automatically when enabled."}
                          </p>
                        )}
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}

      {/* Sticky save bar */}
      {pendingCount > 0 && (
        <div className="sticky bottom-4 flex items-center justify-between bg-card border border-border rounded-xl px-5 py-3 shadow-xl shadow-black/30">
          <div className="flex items-center gap-2 text-sm">
            <AlertTriangle className="w-4 h-4 text-amber-400" />
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
