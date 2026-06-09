import { useState, useEffect } from "react";
import { useAuth } from "@/hooks/useAuth";
import { useLocation } from "wouter";
import { Key, Save, Eye, EyeOff, CheckCircle2, AlertTriangle, Mail, Bell, Search, Globe } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";

interface PlatformSetting {
  key: string;
  label: string;
  description: string;
  category: string;
  hasValue: boolean;
  maskedValue: string;
}

const CATEGORY_META: Record<string, { label: string; icon: React.ElementType; color: string }> = {
  email:         { label: "Email & SMTP",       icon: Mail,         color: "text-blue-400" },
  notifications: { label: "Notifications",       icon: Bell,         color: "text-purple-400" },
  scanning:      { label: "Scanning APIs",        icon: Search,       color: "text-green-400" },
  osint:         { label: "OSINT & Intel",        icon: Globe,        color: "text-yellow-400" },
  general:       { label: "General",              icon: Key,          color: "text-muted-foreground" },
};

const AUTH_HEADER = () => ({ Authorization: `Bearer ${sessionStorage.getItem("access_token")}` });

export default function PlatformSettingsPage() {
  const { user } = useAuth();
  const [, navigate] = useLocation();

  const [settings, setSettings] = useState<PlatformSetting[]>([]);
  const [loading, setLoading] = useState(true);
  const [edits, setEdits] = useState<Record<string, string>>({});
  const [revealed, setRevealed] = useState<Record<string, string>>({});
  const [showKeys, setShowKeys] = useState<Set<string>>(new Set());
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    if (user?.role !== "super_admin") { navigate("/dashboard"); return; }
    fetch("/api/platform/settings", { headers: AUTH_HEADER() })
      .then(r => r.json())
      .then(data => { setSettings(data); setLoading(false); });
  }, [user?.role]);

  const handleReveal = async (key: string) => {
    if (revealed[key] !== undefined) {
      setShowKeys(prev => { const n = new Set(prev); n.has(key) ? n.delete(key) : n.add(key); return n; });
      return;
    }
    const res = await fetch(`/api/platform/settings/raw/${key}`, { headers: AUTH_HEADER() });
    const { value } = await res.json();
    setRevealed(prev => ({ ...prev, [key]: value }));
    setShowKeys(prev => { const n = new Set(prev); n.add(key); return n; });
  };

  const handleSave = async () => {
    if (Object.keys(edits).length === 0) return;
    setSaving(true);
    await fetch("/api/platform/settings", {
      method: "PUT",
      headers: { ...AUTH_HEADER(), "Content-Type": "application/json" },
      body: JSON.stringify(edits),
    });
    setSaving(false);
    setSaved(true);
    setTimeout(() => setSaved(false), 2500);
    setEdits({});
    setRevealed({});
    setShowKeys(new Set());
    const data = await fetch("/api/platform/settings", { headers: AUTH_HEADER() }).then(r => r.json());
    setSettings(data);
  };

  const grouped = settings.reduce((acc, s) => {
    const cat = s.category ?? "general";
    if (!acc[cat]) acc[cat] = [];
    acc[cat].push(s);
    return acc;
  }, {} as Record<string, PlatformSetting[]>);

  const categoryOrder = ["email", "scanning", "notifications", "osint", "general"];
  const orderedGroups = categoryOrder.filter(c => grouped[c]);

  const hasPendingEdits = Object.keys(edits).length > 0;

  return (
    <div className="space-y-6 max-w-2xl">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold">Platform Settings</h1>
          <p className="text-sm text-muted-foreground">
            Third-party API keys and service credentials — visible to super admins only
          </p>
        </div>
        <Button
          size="sm"
          disabled={!hasPendingEdits || saving}
          onClick={handleSave}
          className={cn(saved && "bg-green-600 hover:bg-green-600")}
        >
          {saved
            ? <><CheckCircle2 className="w-3.5 h-3.5 mr-1.5" /> Saved</>
            : saving
              ? "Saving…"
              : <><Save className="w-3.5 h-3.5 mr-1.5" /> Save Changes</>
          }
        </Button>
      </div>

      <div className="bg-amber-500/10 border border-amber-500/30 rounded-xl px-4 py-3 flex items-start gap-2.5">
        <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
        <p className="text-xs text-amber-300 leading-relaxed">
          These credentials are stored in the platform database. Only super admins can view or edit them.
          Values are masked in the UI; click the eye icon to reveal a stored key.
        </p>
      </div>

      {loading && (
        <div className="space-y-4">
          {[...Array(3)].map((_, i) => <Skeleton key={i} className="h-28 rounded-xl" />)}
        </div>
      )}

      {!loading && orderedGroups.map(cat => {
        const meta = CATEGORY_META[cat] ?? CATEGORY_META.general;
        const Icon = meta.icon;
        return (
          <div key={cat} className="bg-card border border-border rounded-xl p-5 space-y-4">
            <div className="flex items-center gap-2 pb-1 border-b border-border">
              <Icon className={cn("w-4 h-4", meta.color)} />
              <h2 className="text-sm font-semibold">{meta.label}</h2>
            </div>

            {grouped[cat].map(setting => {
              const editVal = edits[setting.key];
              const isEdited = editVal !== undefined;
              const isRevealed = showKeys.has(setting.key);
              const revealedVal = revealed[setting.key];

              return (
                <div key={setting.key} className="space-y-1.5">
                  <div className="flex items-center justify-between">
                    <Label className="text-xs font-medium flex items-center gap-1.5">
                      {setting.label}
                      {setting.hasValue && !isEdited && (
                        <span className="text-[9px] px-1.5 py-0.5 rounded bg-green-500/15 text-green-400 border border-green-500/30 font-semibold">
                          SET
                        </span>
                      )}
                      {isEdited && (
                        <span className="text-[9px] px-1.5 py-0.5 rounded bg-amber-500/15 text-amber-400 border border-amber-500/30 font-semibold">
                          UNSAVED
                        </span>
                      )}
                    </Label>
                    {setting.hasValue && (
                      <button
                        onClick={() => handleReveal(setting.key)}
                        className="flex items-center gap-1 text-[10px] text-muted-foreground hover:text-foreground transition-colors"
                      >
                        {isRevealed ? <EyeOff className="w-3 h-3" /> : <Eye className="w-3 h-3" />}
                        {isRevealed ? "Hide" : "Reveal"}
                      </button>
                    )}
                  </div>

                  <div className="relative">
                    <Input
                      type={isRevealed ? "text" : "password"}
                      className="h-9 text-sm font-mono pr-24"
                      placeholder={
                        setting.hasValue && !isEdited && !isRevealed
                          ? setting.maskedValue || "••••••••••••"
                          : `Enter ${setting.label}…`
                      }
                      value={
                        isEdited
                          ? editVal
                          : isRevealed
                            ? (revealedVal ?? "")
                            : ""
                      }
                      onChange={e => setEdits(prev => ({ ...prev, [setting.key]: e.target.value }))}
                    />
                    {setting.hasValue && !isEdited && (
                      <button
                        onClick={() => setEdits(prev => ({ ...prev, [setting.key]: "" }))}
                        className="absolute right-2.5 top-1/2 -translate-y-1/2 text-[10px] text-destructive hover:text-red-400 transition-colors"
                      >
                        Clear
                      </button>
                    )}
                  </div>

                  {setting.description && (
                    <p className="text-[11px] text-muted-foreground leading-relaxed">{setting.description}</p>
                  )}
                </div>
              );
            })}
          </div>
        );
      })}
    </div>
  );
}
