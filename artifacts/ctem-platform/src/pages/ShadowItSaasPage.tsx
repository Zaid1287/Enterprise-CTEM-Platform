import { useState } from "react";
import { apiFetch } from "@/lib/apiFetch";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useToast } from "@/hooks/use-toast";
import { cn } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter,
} from "@/components/ui/dialog";
import {
  Tabs, TabsContent, TabsList, TabsTrigger,
} from "@/components/ui/tabs";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import {
  Sheet, SheetContent, SheetHeader, SheetTitle,
} from "@/components/ui/sheet";
import {
  Shield, RefreshCw, Plus, Trash2, Users, AlertTriangle,
  CheckCircle2, XCircle, Clock, ExternalLink, Eye, EyeOff,
  ShieldAlert, Search, Link2, PlugZap, ChevronDown, ChevronUp,
  Info, KeyRound, Wifi,
} from "lucide-react";

// ── Types ──────────────────────────────────────────────────────────────────────

interface IdpConnection {
  id: number; provider: string; displayName: string; isActive: boolean;
  lastSyncStatus: string; lastSyncAt: string | null; syncedApps: number; syncedUsers: number;
  lastSyncError: string | null; configDomain?: string; configEmail?: string;
  configTenantId?: string; configClientId?: string;
}

interface OauthApp {
  id: number; provider: string; externalId: string; displayName: string; appType: string;
  publisherDomain: string | null; homepageUrl: string | null; logoUrl: string | null;
  scopes: string[] | null; permissionSummary: Record<string, boolean> | null;
  riskScore: number; riskLevel: string;
  riskFactors: Array<{ scope: string; level: string; reason: string }> | null;
  userCount: number; isAdminConsented: boolean; isSanctioned: boolean; status: string;
  firstDiscoveredAt: string; users?: OauthUser[];
}

interface OauthUser {
  id: number; userEmail: string; userDisplayName: string; userDepartment: string | null;
  userJobTitle: string | null; scopesGranted: string[] | null; riskLevel: string; isAdminUser: boolean;
}

interface CredStatus {
  shadow_it_google_sa_json: boolean;
  shadow_it_azure_client_secret: boolean;
  shadow_it_okta_api_token: boolean;
}

// ── Constants ──────────────────────────────────────────────────────────────────

const PROVIDER_META: Record<string, {
  label: string; color: string; bg: string; abbr: string; setupSteps: string[];
}> = {
  google_workspace: {
    label: "Google Workspace",
    color: "#4285F4",
    bg: "rgba(66,133,244,0.12)",
    abbr: "G",
    setupSteps: [
      "Create a Service Account in Google Cloud Console",
      "Enable Domain-Wide Delegation on the service account",
      "In Google Admin → Security → API Controls → Domain-wide delegation, add scopes: admin.directory.user.readonly, admin.directory.user.security",
      "Download the JSON key file and paste the full content into the credential field below",
      "Enter the super admin email (used for impersonation)",
    ],
  },
  microsoft_graph: {
    label: "Microsoft Entra ID",
    color: "#00A4EF",
    bg: "rgba(0,164,239,0.12)",
    abbr: "M",
    setupSteps: [
      "Register an App in Azure AD (App registrations → New registration)",
      "Add Application permissions: Application.Read.All, User.Read.All, DelegatedPermissionGrant.ReadWrite.All",
      "Grant Admin Consent for all permissions",
      "Create a Client Secret under Certificates & secrets",
      "Paste the client secret value into the credential field below, and enter your Tenant ID & Client ID",
    ],
  },
  okta: {
    label: "Okta",
    color: "#007DC1",
    bg: "rgba(0,125,193,0.12)",
    abbr: "O",
    setupSteps: [
      "In Okta Admin Console → Security → API → Tokens, create a new API token",
      "Copy the token and paste it into the credential field below",
      "Enter your Okta domain (e.g. mycompany.okta.com)",
    ],
  },
};

const CRED_KEYS: Record<string, string> = {
  google_workspace: "shadow_it_google_sa_json",
  microsoft_graph: "shadow_it_azure_client_secret",
  okta: "shadow_it_okta_api_token",
};

const CRED_META: Record<string, { label: string; hint: string; isJson: boolean; placeholder: string }> = {
  google_workspace: {
    label: "Service Account JSON Key File",
    hint: "Paste the full contents of the downloaded JSON key file",
    isJson: true,
    placeholder: '{\n  "type": "service_account",\n  "project_id": "my-project",\n  "private_key_id": "...",\n  ...\n}',
  },
  microsoft_graph: {
    label: "Azure App Client Secret",
    hint: "The secret value (not the secret ID) from your Azure App Registration",
    isJson: false,
    placeholder: "Enter client secret value…",
  },
  okta: {
    label: "Okta API Token",
    hint: "Generated from Okta Admin Console → Security → API → Tokens",
    isJson: false,
    placeholder: "SSWS xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
  },
};

const RISK_CONFIG: Record<string, { bg: string; text: string; border: string }> = {
  critical: { bg: "bg-red-500/10",    text: "text-red-400",    border: "border-red-500/20" },
  high:     { bg: "bg-orange-500/10", text: "text-orange-400", border: "border-orange-500/20" },
  medium:   { bg: "bg-yellow-500/10", text: "text-yellow-400", border: "border-yellow-500/20" },
  low:      { bg: "bg-green-500/10",  text: "text-green-400",  border: "border-green-500/20" },
};

const PERM_LABELS: Record<string, string> = {
  canReadFiles: "Read Files", canWriteFiles: "Write Files",
  canReadEmail: "Read Email", canSendEmail: "Send Email",
  canReadCalendar: "Read Calendar", canManageUsers: "Manage Users",
  hasAdminAccess: "Admin Access",
};

// ── Helper components ──────────────────────────────────────────────────────────

function RiskBadge({ level }: { level: string }) {
  const cfg = RISK_CONFIG[level] ?? { bg: "bg-muted", text: "text-muted-foreground", border: "border-border" };
  return (
    <span className={cn("inline-flex items-center px-2 py-0.5 rounded-full text-xs font-semibold border capitalize", cfg.bg, cfg.text, cfg.border)}>
      {level}
    </span>
  );
}

function KpiCard({ label, value, icon, accent }: { label: string; value: number; icon: React.ReactNode; accent: string }) {
  return (
    <div className="rounded-xl border bg-card p-4 flex items-center gap-3">
      <div className={cn("p-2.5 rounded-lg", accent)}>
        {icon}
      </div>
      <div>
        <p className="text-2xl font-bold leading-none">{value}</p>
        <p className="text-xs text-muted-foreground mt-1">{label}</p>
      </div>
    </div>
  );
}

function formatSyncTime(dt: string | null): string {
  if (!dt) return "Never synced";
  const d = new Date(dt);
  const mins = Math.floor((Date.now() - d.getTime()) / 60000);
  if (mins < 2) return "Just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

// ── Main Component ─────────────────────────────────────────────────────────────

export default function ShadowItSaasPage() {
  const qc = useQueryClient();
  const { toast } = useToast();

  // UI state
  const [syncing, setSyncing] = useState<number | null>(null);
  const [showAddIdp, setShowAddIdp] = useState(false);
  const [addProvider, setAddProvider] = useState("google_workspace");
  const [addForm, setAddForm] = useState<Record<string, string>>({});
  const [credentialValue, setCredentialValue] = useState("");
  const [showCred, setShowCred] = useState(false);
  const [savingAll, setSavingAll] = useState(false);
  const [showSetupSteps, setShowSetupSteps] = useState(false);
  const [selectedApp, setSelectedApp] = useState<OauthApp | null>(null);
  const [filterRisk, setFilterRisk] = useState("all");
  const [filterProvider, setFilterProvider] = useState("all");
  const [filterSanctioned, setFilterSanctioned] = useState("all");
  const [search, setSearch] = useState("");

  // Data queries
  const idpQ = useQuery<IdpConnection[]>({
    queryKey: ["shadow-it-idp"],
    queryFn: () => apiFetch("/api/shadow-it/idp-connections"),
    refetchInterval: 30000,
  });

  const credStatusQ = useQuery<CredStatus>({
    queryKey: ["shadow-it-cred-status"],
    queryFn: () => apiFetch("/api/shadow-it/idp-credential-status"),
  });

  const appsQ = useQuery<{ items: OauthApp[]; total: number }>({
    queryKey: ["shadow-it-oauth-apps", filterRisk, filterProvider, filterSanctioned],
    queryFn: () => {
      const p = new URLSearchParams({ limit: "200" });
      if (filterRisk !== "all") p.set("riskLevel", filterRisk);
      if (filterProvider !== "all") p.set("provider", filterProvider);
      if (filterSanctioned !== "all") p.set("isSanctioned", filterSanctioned);
      return apiFetch(`/api/shadow-it/oauth-apps?${p}`);
    },
    refetchInterval: 60000,
  });

  const appDetailQ = useQuery<OauthApp>({
    queryKey: ["shadow-it-oauth-app", selectedApp?.id],
    queryFn: () => apiFetch(`/api/shadow-it/oauth-apps/${selectedApp!.id}`),
    enabled: !!selectedApp,
  });

  // Mutations
  const addIdpMut = useMutation({
    mutationFn: (data: Record<string, string>) =>
      apiFetch("/api/shadow-it/idp-connections", { method: "POST", body: JSON.stringify(data) }),
  });

  const deleteIdpMut = useMutation({
    mutationFn: (id: number) =>
      apiFetch(`/api/shadow-it/idp-connections/${id}`, { method: "DELETE" }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["shadow-it-idp"] });
      qc.invalidateQueries({ queryKey: ["shadow-it-oauth-apps"] });
    },
  });

  const toggleSanctioned = useMutation({
    mutationFn: ({ id, isSanctioned }: { id: number; isSanctioned: boolean }) =>
      apiFetch(`/api/shadow-it/oauth-apps/${id}`, { method: "PATCH", body: JSON.stringify({ isSanctioned }) }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["shadow-it-oauth-apps"] }),
  });

  // Derived state
  const idpList = idpQ.data ?? [];
  const appList = appsQ.data?.items ?? [];
  const totalOauth = appsQ.data?.total ?? 0;
  const unsanctionedCount = appList.filter(a => !a.isSanctioned).length;
  const highRiskCount = appList.filter(a => a.riskLevel === "critical" || a.riskLevel === "high").length;
  const appDetail = appDetailQ.data ?? selectedApp;

  const filteredApps = search.trim()
    ? appList.filter(a =>
        a.displayName.toLowerCase().includes(search.toLowerCase()) ||
        (a.publisherDomain ?? "").toLowerCase().includes(search.toLowerCase())
      )
    : appList;

  // Connect IdP — saves credential then creates connection
  const handleConnectIdp = async () => {
    if (!addForm.displayName) return;
    setSavingAll(true);

    // Step 1: Save credential to platform settings
    if (credentialValue.trim()) {
      try {
        await apiFetch("/api/shadow-it/idp-credentials", {
          method: "PUT",
          body: JSON.stringify({ key: CRED_KEYS[addProvider], value: credentialValue.trim() }),
        });
        qc.invalidateQueries({ queryKey: ["shadow-it-cred-status"] });
      } catch (err: any) {
        toast({
          title: "Credential not saved",
          description: err?.message ?? "Failed to save credential. Ensure you have admin access.",
          variant: "destructive",
        });
        // Continue anyway — IdP connection record can still be created
      }
    }

    // Step 2: Create the IdP connection record
    try {
      await addIdpMut.mutateAsync({ ...addForm, provider: addProvider });
      qc.invalidateQueries({ queryKey: ["shadow-it-idp"] });
      toast({
        title: "IdP connected",
        description: `${PROVIDER_META[addProvider]?.label} connected. Click Sync to begin discovering OAuth apps.`,
      });
      setShowAddIdp(false);
      setAddForm({});
      setCredentialValue("");
      setShowSetupSteps(false);
    } catch (err: any) {
      toast({ title: "Connection failed", description: err?.message ?? "Unknown error", variant: "destructive" });
    }
    setSavingAll(false);
  };

  // Sync a single connection
  const syncConn = async (id: number) => {
    setSyncing(id);
    try {
      await apiFetch(`/api/shadow-it/idp-connections/${id}/sync`, { method: "POST" });
      toast({ title: "Sync started", description: "Background sync in progress. Data will update shortly." });
      await new Promise(r => setTimeout(r, 2500));
      qc.invalidateQueries({ queryKey: ["shadow-it-idp"] });
      qc.invalidateQueries({ queryKey: ["shadow-it-oauth-apps"] });
    } catch (err: any) {
      toast({ title: "Sync failed", description: err?.message, variant: "destructive" });
    }
    setSyncing(null);
  };

  const credMeta = CRED_META[addProvider];
  const credKey = CRED_KEYS[addProvider];
  const credStatus = credStatusQ.data;
  const credAlreadySaved = credStatus?.[credKey as keyof CredStatus] ?? false;

  return (
    <div className="p-6 space-y-5">

      {/* ── Hero ─────────────────────────────────────────────────────────────── */}
      <div className="rounded-xl bg-card border border-border/50 overflow-hidden">
        <div className="h-1 bg-gradient-to-r from-purple-500 via-violet-500 to-indigo-500" />
        <div className="px-6 py-5 flex items-center justify-between flex-wrap gap-4">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-lg bg-purple-500/10 border border-purple-500/20">
              <Shield className="h-6 w-6 text-purple-400" />
            </div>
            <div>
              <h1 className="text-xl font-bold tracking-tight">SaaS &amp; OAuth Discovery</h1>
              <p className="text-sm text-muted-foreground mt-0.5">
                Identity Provider integrations · OAuth scope risk · employee attribution
              </p>
            </div>
          </div>
          <Button onClick={() => setShowAddIdp(true)} className="bg-purple-600 hover:bg-purple-700 text-white">
            <Plus className="h-4 w-4 mr-2" /> Connect IdP
          </Button>
        </div>
      </div>

      {/* ── KPI Strip ────────────────────────────────────────────────────────── */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard
          label="IdP Connections"
          value={idpList.length}
          accent="bg-purple-500/10"
          icon={<PlugZap className="h-4 w-4 text-purple-400" />}
        />
        <KpiCard
          label="OAuth Apps Discovered"
          value={totalOauth}
          accent="bg-blue-500/10"
          icon={<Shield className="h-4 w-4 text-blue-400" />}
        />
        <KpiCard
          label="Unsanctioned Apps"
          value={unsanctionedCount}
          accent="bg-orange-500/10"
          icon={<AlertTriangle className="h-4 w-4 text-orange-400" />}
        />
        <KpiCard
          label="High / Critical Risk"
          value={highRiskCount}
          accent="bg-red-500/10"
          icon={<ShieldAlert className="h-4 w-4 text-red-400" />}
        />
      </div>

      {/* ── Tabs ─────────────────────────────────────────────────────────────── */}
      <Tabs defaultValue="connections">
        <TabsList className="bg-muted/50 border border-border/50 h-10">
          <TabsTrigger value="connections" className="gap-2">
            <Link2 className="h-3.5 w-3.5" />
            IdP Connections
            {idpList.length > 0 && (
              <span className="ml-1 rounded-full bg-purple-500/20 text-purple-400 text-xs px-1.5 py-0.5 font-semibold">
                {idpList.length}
              </span>
            )}
          </TabsTrigger>
          <TabsTrigger value="apps" className="gap-2">
            <Shield className="h-3.5 w-3.5" />
            OAuth Apps
            {totalOauth > 0 && (
              <span className="ml-1 rounded-full bg-blue-500/20 text-blue-400 text-xs px-1.5 py-0.5 font-semibold">
                {totalOauth}
              </span>
            )}
          </TabsTrigger>
        </TabsList>

        {/* ══ IdP Connections Tab ══════════════════════════════════════════════ */}
        <TabsContent value="connections" className="mt-5">
          {idpQ.isLoading && (
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
              {[0, 1].map(i => (
                <div key={i} className="rounded-xl border bg-card p-5 animate-pulse h-40" />
              ))}
            </div>
          )}

          {!idpQ.isLoading && idpList.length === 0 && (
            <div className="rounded-xl border-2 border-dashed border-border bg-card/50 py-16 text-center">
              <div className="mx-auto w-14 h-14 rounded-full bg-purple-500/10 flex items-center justify-center mb-4">
                <PlugZap className="h-7 w-7 text-purple-400" />
              </div>
              <h3 className="font-semibold text-base mb-1">No identity providers connected</h3>
              <p className="text-sm text-muted-foreground max-w-sm mx-auto mb-5">
                Connect Google Workspace, Microsoft Entra ID, or Okta to automatically discover OAuth apps granted by your employees.
              </p>
              <Button onClick={() => setShowAddIdp(true)} className="bg-purple-600 hover:bg-purple-700 text-white">
                <Plus className="h-4 w-4 mr-2" /> Connect your first IdP
              </Button>
            </div>
          )}

          {idpList.length > 0 && (
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
              {idpList.map(conn => {
                const meta = PROVIDER_META[conn.provider];
                const isNever = conn.lastSyncStatus === "never";
                const isFailed = conn.lastSyncStatus === "failed";
                const isSyncing = syncing === conn.id;
                return (
                  <div key={conn.id} className={cn(
                    "rounded-xl border bg-card overflow-hidden flex flex-col transition-shadow hover:shadow-md",
                    isFailed && "border-red-500/30",
                    isNever && "border-dashed",
                  )}>
                    {/* Card top strip */}
                    <div className="h-1" style={{ background: meta?.color ?? "#888" }} />
                    <div className="p-5 flex-1 flex flex-col gap-4">
                      {/* Provider header */}
                      <div className="flex items-start justify-between gap-3">
                        <div className="flex items-center gap-3">
                          <div
                            className="h-11 w-11 rounded-xl flex items-center justify-center text-white font-bold text-base flex-shrink-0"
                            style={{ background: meta?.color ?? "#888" }}
                          >
                            {meta?.abbr ?? conn.provider[0].toUpperCase()}
                          </div>
                          <div className="min-w-0">
                            <p className="font-semibold text-sm leading-tight truncate">{conn.displayName}</p>
                            <p className="text-xs text-muted-foreground mt-0.5">{meta?.label ?? conn.provider}</p>
                          </div>
                        </div>
                        <div className="flex-shrink-0">
                          {conn.lastSyncStatus === "success" && (
                            <span className="inline-flex items-center gap-1 text-xs text-green-500 font-medium">
                              <CheckCircle2 className="h-3.5 w-3.5" /> Synced
                            </span>
                          )}
                          {isFailed && (
                            <span className="inline-flex items-center gap-1 text-xs text-red-500 font-medium">
                              <XCircle className="h-3.5 w-3.5" /> Failed
                            </span>
                          )}
                          {isNever && (
                            <span className="inline-flex items-center gap-1 text-xs text-muted-foreground font-medium">
                              <Clock className="h-3.5 w-3.5" /> Not synced
                            </span>
                          )}
                        </div>
                      </div>

                      {/* Config details */}
                      <div className="space-y-1 text-xs text-muted-foreground">
                        {conn.configEmail && <p><span className="font-medium text-foreground/70">Admin:</span> {conn.configEmail}</p>}
                        {conn.configDomain && <p><span className="font-medium text-foreground/70">Domain:</span> {conn.configDomain}</p>}
                        {conn.configTenantId && <p><span className="font-medium text-foreground/70">Tenant:</span> {conn.configTenantId}</p>}
                        {conn.configClientId && <p><span className="font-medium text-foreground/70">Client ID:</span> {conn.configClientId.slice(0, 8)}…</p>}
                      </div>

                      {/* Stats */}
                      <div className="flex items-center gap-3 pt-1">
                        <div className="flex items-center gap-1.5 text-xs">
                          <Shield className="h-3 w-3 text-muted-foreground" />
                          <span className="font-semibold">{conn.syncedApps}</span>
                          <span className="text-muted-foreground">apps</span>
                        </div>
                        <div className="w-px h-3 bg-border" />
                        <div className="flex items-center gap-1.5 text-xs">
                          <Users className="h-3 w-3 text-muted-foreground" />
                          <span className="font-semibold">{conn.syncedUsers}</span>
                          <span className="text-muted-foreground">users</span>
                        </div>
                        {conn.lastSyncAt && (
                          <>
                            <div className="w-px h-3 bg-border" />
                            <span className="text-xs text-muted-foreground">{formatSyncTime(conn.lastSyncAt)}</span>
                          </>
                        )}
                      </div>

                      {/* Error message */}
                      {conn.lastSyncError && (
                        <div className="rounded-lg bg-red-500/8 border border-red-500/20 px-3 py-2 text-xs text-red-400">
                          {conn.lastSyncError.slice(0, 120)}{conn.lastSyncError.length > 120 ? "…" : ""}
                        </div>
                      )}
                    </div>

                    {/* Card footer actions */}
                    <div className="px-5 py-3 border-t border-border/50 flex items-center justify-between bg-muted/20">
                      <Button
                        size="sm"
                        variant="outline"
                        disabled={isSyncing}
                        onClick={() => syncConn(conn.id)}
                        className="h-8 text-xs gap-1.5"
                      >
                        <RefreshCw className={cn("h-3.5 w-3.5", isSyncing && "animate-spin")} />
                        {isSyncing ? "Syncing…" : "Sync Now"}
                      </Button>
                      <Button
                        size="sm"
                        variant="ghost"
                        className="h-8 text-xs text-red-400 hover:text-red-300 hover:bg-red-500/10"
                        onClick={() => {
                          if (confirm(`Delete the "${conn.displayName}" connection? This will not remove discovered OAuth apps.`)) {
                            deleteIdpMut.mutate(conn.id);
                          }
                        }}
                      >
                        <Trash2 className="h-3.5 w-3.5 mr-1" /> Remove
                      </Button>
                    </div>
                  </div>
                );
              })}

              {/* Add another button */}
              <button
                onClick={() => setShowAddIdp(true)}
                className="rounded-xl border-2 border-dashed border-border/60 bg-card/30 hover:border-purple-500/40 hover:bg-purple-500/5 transition-all flex flex-col items-center justify-center gap-2 py-10 text-sm text-muted-foreground hover:text-purple-400 min-h-[180px]"
              >
                <Plus className="h-7 w-7 opacity-50" />
                <span>Connect another IdP</span>
              </button>
            </div>
          )}
        </TabsContent>

        {/* ══ OAuth Apps Tab ═══════════════════════════════════════════════════ */}
        <TabsContent value="apps" className="mt-5 space-y-5">

          {/* Filter bar */}
          <div className="flex flex-wrap gap-3 items-center">
            <div className="relative flex-1 min-w-[200px] max-w-sm">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search apps…"
                value={search}
                onChange={e => setSearch(e.target.value)}
                className="pl-9 h-9"
              />
            </div>
            <Select value={filterProvider} onValueChange={setFilterProvider}>
              <SelectTrigger className="w-[170px] h-9"><SelectValue placeholder="All providers" /></SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All providers</SelectItem>
                <SelectItem value="google_workspace">Google Workspace</SelectItem>
                <SelectItem value="microsoft_graph">Microsoft Entra ID</SelectItem>
                <SelectItem value="okta">Okta</SelectItem>
              </SelectContent>
            </Select>
            <Select value={filterRisk} onValueChange={setFilterRisk}>
              <SelectTrigger className="w-[150px] h-9"><SelectValue placeholder="All risk" /></SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All risk levels</SelectItem>
                <SelectItem value="critical">Critical</SelectItem>
                <SelectItem value="high">High</SelectItem>
                <SelectItem value="medium">Medium</SelectItem>
                <SelectItem value="low">Low</SelectItem>
              </SelectContent>
            </Select>
            <Select value={filterSanctioned} onValueChange={setFilterSanctioned}>
              <SelectTrigger className="w-[160px] h-9"><SelectValue placeholder="All apps" /></SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All apps</SelectItem>
                <SelectItem value="false">Unsanctioned only</SelectItem>
                <SelectItem value="true">Sanctioned only</SelectItem>
              </SelectContent>
            </Select>
            {(filterRisk !== "all" || filterProvider !== "all" || filterSanctioned !== "all" || search) && (
              <Button
                size="sm" variant="ghost" className="h-9 text-xs text-muted-foreground"
                onClick={() => { setFilterRisk("all"); setFilterProvider("all"); setFilterSanctioned("all"); setSearch(""); }}
              >
                Clear filters
              </Button>
            )}
          </div>

          {/* Empty state */}
          {!appsQ.isLoading && filteredApps.length === 0 && (
            <div className="rounded-xl border-2 border-dashed border-border bg-card/50 py-16 text-center">
              <Wifi className="h-10 w-10 text-muted-foreground mx-auto mb-3 opacity-50" />
              <p className="font-medium mb-1">
                {totalOauth === 0 ? "No OAuth apps discovered yet" : "No apps match your filters"}
              </p>
              <p className="text-sm text-muted-foreground">
                {totalOauth === 0
                  ? "Connect an Identity Provider and click Sync to start discovering OAuth apps."
                  : "Try adjusting your search or filter criteria."}
              </p>
            </div>
          )}

          {/* Loading skeleton */}
          {appsQ.isLoading && (
            <div className="grid grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
              {Array.from({ length: 8 }).map((_, i) => (
                <div key={i} className="rounded-xl border bg-card p-4 animate-pulse h-52" />
              ))}
            </div>
          )}

          {/* App card grid */}
          {!appsQ.isLoading && filteredApps.length > 0 && (
            <>
              {search && (
                <p className="text-sm text-muted-foreground">
                  Showing {filteredApps.length} result{filteredApps.length !== 1 ? "s" : ""} for "{search}"
                </p>
              )}
              <div className="grid grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
                {filteredApps.map(app => {
                  const riskCfg = RISK_CONFIG[app.riskLevel] ?? RISK_CONFIG.low;
                  const provMeta = PROVIDER_META[app.provider];
                  const topPerms = app.permissionSummary
                    ? Object.entries(app.permissionSummary)
                        .filter(([k, v]) => v && !["scopeCount", "highestRisk"].includes(k))
                        .slice(0, 3)
                    : [];

                  return (
                    <div
                      key={app.id}
                      onClick={() => setSelectedApp(app)}
                      className={cn(
                        "rounded-xl border bg-card overflow-hidden flex flex-col cursor-pointer transition-all hover:shadow-md hover:border-border",
                        !app.isSanctioned && "border-orange-500/20",
                        app.riskLevel === "critical" && "border-red-500/20",
                      )}
                    >
                      {/* Risk color strip */}
                      <div className="h-1" style={{ background: RISK_CONFIG[app.riskLevel]?.text.replace("text-", "") === "red-400" ? "#ef4444" : app.riskLevel === "high" ? "#f97316" : app.riskLevel === "medium" ? "#eab308" : "#22c55e" }} />

                      <div className="p-4 flex-1 flex flex-col gap-3">
                        {/* App header */}
                        <div className="flex items-start gap-3">
                          <div className="flex-shrink-0">
                            {app.logoUrl ? (
                              <img
                                src={app.logoUrl}
                                className="h-10 w-10 rounded-lg object-contain bg-white p-0.5"
                                alt=""
                                onError={e => { (e.target as HTMLImageElement).style.display = "none"; }}
                              />
                            ) : (
                              <div
                                className="h-10 w-10 rounded-lg flex items-center justify-center text-sm font-bold text-white"
                                style={{ background: provMeta?.color ?? "#6366f1" }}
                              >
                                {app.displayName.slice(0, 2).toUpperCase()}
                              </div>
                            )}
                          </div>
                          <div className="min-w-0 flex-1">
                            <p className="font-semibold text-sm leading-tight truncate">{app.displayName}</p>
                            {app.publisherDomain && (
                              <p className="text-xs text-muted-foreground truncate mt-0.5">{app.publisherDomain}</p>
                            )}
                          </div>
                        </div>

                        {/* Risk + provider row */}
                        <div className="flex items-center gap-2 flex-wrap">
                          <RiskBadge level={app.riskLevel} />
                          <span
                            className="inline-flex items-center text-xs px-2 py-0.5 rounded-full font-medium"
                            style={{ background: provMeta?.bg ?? "rgba(100,100,100,0.12)", color: provMeta?.color ?? "#888" }}
                          >
                            {provMeta?.abbr ?? app.provider.slice(0, 1).toUpperCase()}
                          </span>
                          {!app.isSanctioned && (
                            <span className="inline-flex items-center gap-1 text-xs text-orange-400">
                              <AlertTriangle className="h-3 w-3" /> Unsanctioned
                            </span>
                          )}
                        </div>

                        {/* Users */}
                        <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
                          <Users className="h-3.5 w-3.5" />
                          <span className="font-medium text-foreground">{app.userCount}</span>
                          <span>user{app.userCount !== 1 ? "s" : ""} with access</span>
                        </div>

                        {/* Permission chips */}
                        {topPerms.length > 0 && (
                          <div className="flex flex-wrap gap-1">
                            {topPerms.map(([k]) => (
                              <span key={k} className="text-xs bg-red-500/8 border border-red-500/15 text-red-400 px-1.5 py-0.5 rounded-md">
                                {PERM_LABELS[k] ?? k}
                              </span>
                            ))}
                          </div>
                        )}
                        {app.scopes && app.scopes.length > 0 && topPerms.length === 0 && (
                          <p className="text-xs text-muted-foreground">{app.scopes.length} scope{app.scopes.length !== 1 ? "s" : ""} granted</p>
                        )}
                      </div>

                      {/* Sanction toggle footer */}
                      <div
                        className="px-4 py-2.5 border-t border-border/50 bg-muted/20"
                        onClick={e => e.stopPropagation()}
                      >
                        <button
                          className={cn(
                            "w-full text-xs font-medium py-1.5 rounded-lg transition-colors flex items-center justify-center gap-1.5",
                            app.isSanctioned
                              ? "bg-green-500/10 text-green-400 hover:bg-green-500/20"
                              : "bg-orange-500/10 text-orange-400 hover:bg-orange-500/20"
                          )}
                          onClick={() => toggleSanctioned.mutate({ id: app.id, isSanctioned: !app.isSanctioned })}
                          disabled={toggleSanctioned.isPending}
                        >
                          {app.isSanctioned
                            ? <><CheckCircle2 className="h-3.5 w-3.5" /> Sanctioned — click to revoke</>
                            : <><AlertTriangle className="h-3.5 w-3.5" /> Mark as Sanctioned</>
                          }
                        </button>
                      </div>
                    </div>
                  );
                })}
              </div>
            </>
          )}
        </TabsContent>
      </Tabs>

      {/* ══ Connect IdP Dialog ═══════════════════════════════════════════════════ */}
      <Dialog open={showAddIdp} onOpenChange={open => {
        if (!open) { setAddForm({}); setCredentialValue(""); setShowSetupSteps(false); }
        setShowAddIdp(open);
      }}>
        <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <PlugZap className="h-5 w-5 text-purple-400" />
              Connect Identity Provider
            </DialogTitle>
          </DialogHeader>

          <div className="space-y-5 pt-1">
            {/* Provider select */}
            <div className="grid grid-cols-3 gap-3">
              {Object.entries(PROVIDER_META).map(([key, meta]) => (
                <button
                  key={key}
                  onClick={() => { setAddProvider(key); setCredentialValue(""); setShowCred(false); }}
                  className={cn(
                    "flex flex-col items-center gap-2 rounded-xl border p-4 text-center transition-all",
                    addProvider === key
                      ? "border-purple-500 bg-purple-500/10 shadow-sm"
                      : "border-border hover:border-border hover:bg-muted/50"
                  )}
                >
                  <div
                    className="h-10 w-10 rounded-xl flex items-center justify-center text-white font-bold text-sm"
                    style={{ background: meta.color }}
                  >
                    {meta.abbr}
                  </div>
                  <span className="text-xs font-medium leading-tight">{meta.label}</span>
                </button>
              ))}
            </div>

            {/* Connection name */}
            <div>
              <Label className="text-sm font-medium">Connection Name</Label>
              <Input
                className="mt-1.5"
                placeholder={`My ${PROVIDER_META[addProvider]?.label} connection`}
                value={addForm.displayName ?? ""}
                onChange={e => setAddForm(f => ({ ...f, displayName: e.target.value }))}
              />
            </div>

            {/* Provider-specific fields */}
            {addProvider === "google_workspace" && (
              <div>
                <Label className="text-sm font-medium">Super Admin Email</Label>
                <Input
                  className="mt-1.5"
                  placeholder="admin@yourcompany.com"
                  value={addForm.configEmail ?? ""}
                  onChange={e => setAddForm(f => ({ ...f, configEmail: e.target.value }))}
                />
                <p className="text-xs text-muted-foreground mt-1.5">Used for Domain-Wide Delegation impersonation to enumerate apps</p>
              </div>
            )}

            {addProvider === "microsoft_graph" && (
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <Label className="text-sm font-medium">Azure Tenant ID</Label>
                  <Input
                    className="mt-1.5"
                    placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                    value={addForm.configTenantId ?? ""}
                    onChange={e => setAddForm(f => ({ ...f, configTenantId: e.target.value }))}
                  />
                </div>
                <div>
                  <Label className="text-sm font-medium">App Registration Client ID</Label>
                  <Input
                    className="mt-1.5"
                    placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                    value={addForm.configClientId ?? ""}
                    onChange={e => setAddForm(f => ({ ...f, configClientId: e.target.value }))}
                  />
                </div>
              </div>
            )}

            {addProvider === "okta" && (
              <div>
                <Label className="text-sm font-medium">Okta Domain</Label>
                <Input
                  className="mt-1.5"
                  placeholder="mycompany.okta.com"
                  value={addForm.configDomain ?? ""}
                  onChange={e => setAddForm(f => ({ ...f, configDomain: e.target.value }))}
                />
              </div>
            )}

            {/* Credential section */}
            <div className={cn(
              "rounded-xl border p-4 space-y-3",
              credAlreadySaved ? "border-green-500/30 bg-green-500/5" : "border-purple-500/30 bg-purple-500/5"
            )}>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <KeyRound className="h-4 w-4 text-purple-400" />
                  <span className="text-sm font-semibold">
                    {credMeta?.label}
                  </span>
                  {credAlreadySaved && (
                    <span className="inline-flex items-center gap-1 text-xs text-green-500 font-medium">
                      <CheckCircle2 className="h-3 w-3" /> Already saved
                    </span>
                  )}
                </div>
              </div>

              <p className="text-xs text-muted-foreground">{credMeta?.hint}</p>

              {credAlreadySaved && !credentialValue && (
                <div className="rounded-lg bg-green-500/10 border border-green-500/20 px-3 py-2 text-xs text-green-400 flex items-center gap-2">
                  <CheckCircle2 className="h-3.5 w-3.5 flex-shrink-0" />
                  Credential is already stored in platform settings. Leave blank to keep using it, or paste a new value to update.
                </div>
              )}

              <div className="relative">
                {credMeta?.isJson ? (
                  <Textarea
                    rows={5}
                    className="font-mono text-xs resize-none bg-background"
                    placeholder={credMeta.placeholder}
                    value={credentialValue}
                    onChange={e => setCredentialValue(e.target.value)}
                  />
                ) : (
                  <div className="relative">
                    <Input
                      type={showCred ? "text" : "password"}
                      className="pr-10 font-mono text-xs bg-background"
                      placeholder={credMeta?.placeholder}
                      value={credentialValue}
                      onChange={e => setCredentialValue(e.target.value)}
                    />
                    <button
                      type="button"
                      className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                      onClick={() => setShowCred(v => !v)}
                    >
                      {showCred ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                    </button>
                  </div>
                )}
              </div>

              <div className="flex items-start gap-2 text-xs text-muted-foreground">
                <Info className="h-3.5 w-3.5 mt-0.5 flex-shrink-0 text-purple-400" />
                <span>Stored securely in platform settings as <code className="bg-muted px-1 py-0.5 rounded text-xs">{credKey}</code>. Only admins and super admins can set or read this credential.</span>
              </div>
            </div>

            {/* Setup steps collapsible */}
            <div className="rounded-xl border border-border/50 overflow-hidden">
              <button
                className="w-full flex items-center justify-between px-4 py-3 text-sm font-medium hover:bg-muted/50 transition-colors"
                onClick={() => setShowSetupSteps(v => !v)}
              >
                <span className="flex items-center gap-2">
                  <Info className="h-4 w-4 text-muted-foreground" />
                  Setup instructions for {PROVIDER_META[addProvider]?.label}
                </span>
                {showSetupSteps ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
              </button>
              {showSetupSteps && (
                <div className="px-4 pb-4 pt-1 space-y-2 border-t border-border/50">
                  {PROVIDER_META[addProvider]?.setupSteps.map((step, i) => (
                    <div key={i} className="flex gap-3 text-sm text-muted-foreground">
                      <span className="flex-shrink-0 w-5 h-5 rounded-full bg-purple-500/20 text-purple-400 text-xs flex items-center justify-center font-bold mt-0.5">
                        {i + 1}
                      </span>
                      <span className="leading-relaxed">{step}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>

          <DialogFooter className="mt-2">
            <Button variant="outline" onClick={() => { setShowAddIdp(false); setAddForm({}); setCredentialValue(""); }}>
              Cancel
            </Button>
            <Button
              disabled={!addForm.displayName || savingAll}
              onClick={handleConnectIdp}
              className="bg-purple-600 hover:bg-purple-700 text-white"
            >
              {savingAll ? (
                <><RefreshCw className="h-4 w-4 mr-2 animate-spin" /> Connecting…</>
              ) : (
                <><PlugZap className="h-4 w-4 mr-2" /> Connect &amp; Save Credential</>
              )}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* ══ App Detail Sheet ══════════════════════════════════════════════════════ */}
      <Sheet open={!!selectedApp} onOpenChange={open => !open && setSelectedApp(null)}>
        <SheetContent className="w-full sm:max-w-xl overflow-y-auto">
          {appDetail && (
            <>
              <SheetHeader className="pb-5">
                <SheetTitle className="flex items-center gap-3">
                  {appDetail.logoUrl ? (
                    <img src={appDetail.logoUrl} className="h-9 w-9 rounded-lg bg-white p-0.5 object-contain" alt="" />
                  ) : (
                    <div
                      className="h-9 w-9 rounded-lg flex items-center justify-center text-sm font-bold text-white"
                      style={{ background: PROVIDER_META[appDetail.provider]?.color ?? "#6366f1" }}
                    >
                      {appDetail.displayName.slice(0, 2).toUpperCase()}
                    </div>
                  )}
                  <div className="min-w-0">
                    <p className="font-semibold truncate">{appDetail.displayName}</p>
                    {appDetail.publisherDomain && (
                      <p className="text-xs text-muted-foreground font-normal">{appDetail.publisherDomain}</p>
                    )}
                  </div>
                </SheetTitle>
              </SheetHeader>

              <div className="space-y-6">
                {/* KPI row */}
                <div className="grid grid-cols-3 gap-3">
                  <div className="rounded-xl border bg-card p-3 text-center">
                    <p className="text-xs text-muted-foreground mb-1.5">Risk Level</p>
                    <RiskBadge level={appDetail.riskLevel} />
                  </div>
                  <div className="rounded-xl border bg-card p-3 text-center">
                    <p className="text-xs text-muted-foreground mb-1">Users</p>
                    <p className="text-xl font-bold">{appDetail.userCount}</p>
                  </div>
                  <div className="rounded-xl border bg-card p-3 text-center">
                    <p className="text-xs text-muted-foreground mb-1">Status</p>
                    <p className={cn("text-sm font-semibold", appDetail.isSanctioned ? "text-green-400" : "text-orange-400")}>
                      {appDetail.isSanctioned ? "Sanctioned" : "Unsanctioned"}
                    </p>
                  </div>
                </div>

                {/* Provider info */}
                <div className="rounded-xl border bg-card p-4 space-y-2">
                  <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-3">App Details</p>
                  <div className="grid grid-cols-2 gap-2 text-sm">
                    <div>
                      <span className="text-muted-foreground text-xs">Provider</span>
                      <p className="font-medium">{PROVIDER_META[appDetail.provider]?.label ?? appDetail.provider}</p>
                    </div>
                    <div>
                      <span className="text-muted-foreground text-xs">App Type</span>
                      <p className="font-medium capitalize">{appDetail.appType}</p>
                    </div>
                    <div>
                      <span className="text-muted-foreground text-xs">Risk Score</span>
                      <p className="font-medium">{appDetail.riskScore}/100</p>
                    </div>
                    <div>
                      <span className="text-muted-foreground text-xs">Admin Consented</span>
                      <p className={cn("font-medium", appDetail.isAdminConsented ? "text-orange-400" : "text-muted-foreground")}>
                        {appDetail.isAdminConsented ? "Yes" : "No"}
                      </p>
                    </div>
                  </div>
                </div>

                {/* Permissions */}
                {appDetail.permissionSummary && (
                  <div>
                    <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-3">Effective Permissions</p>
                    <div className="grid grid-cols-2 gap-2">
                      {Object.entries(appDetail.permissionSummary)
                        .filter(([k]) => !["scopeCount", "highestRisk"].includes(k))
                        .map(([k, v]) => (
                          <div key={k} className={cn(
                            "flex items-center gap-2 p-2.5 rounded-lg text-xs border",
                            v ? "bg-red-500/8 border-red-500/15 text-red-400" : "bg-muted/50 border-border text-muted-foreground"
                          )}>
                            {v
                              ? <AlertTriangle className="h-3.5 w-3.5 flex-shrink-0" />
                              : <CheckCircle2 className="h-3.5 w-3.5 flex-shrink-0" />
                            }
                            {PERM_LABELS[k] ?? k}
                          </div>
                        ))}
                    </div>
                  </div>
                )}

                {/* Scope risk breakdown */}
                {appDetail.riskFactors && appDetail.riskFactors.length > 0 && (
                  <div>
                    <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-3">Scope Risk Breakdown</p>
                    <div className="space-y-1.5 max-h-52 overflow-y-auto pr-1">
                      {appDetail.riskFactors.map((f, i) => (
                        <div key={i} className="flex items-start justify-between gap-3 text-xs p-2.5 rounded-lg border border-border bg-card">
                          <code className="text-xs flex-1 break-all text-muted-foreground">{f.scope}</code>
                          <div className="text-right shrink-0">
                            <RiskBadge level={f.level} />
                            {f.reason && <p className="text-muted-foreground mt-1">{f.reason}</p>}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Employees with access */}
                {appDetail.users && appDetail.users.length > 0 && (
                  <div>
                    <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-3">
                      Employees with Access ({appDetail.users.length})
                    </p>
                    <div className="space-y-1.5 max-h-60 overflow-y-auto pr-1">
                      {appDetail.users.map(u => (
                        <div key={u.id} className="flex items-center justify-between p-3 rounded-lg border border-border bg-card gap-2">
                          <div className="min-w-0 flex-1">
                            <p className="font-medium text-sm truncate">{u.userDisplayName}</p>
                            <p className="text-xs text-muted-foreground truncate">{u.userEmail}</p>
                            {u.userDepartment && (
                              <p className="text-xs text-muted-foreground truncate">
                                {u.userDepartment}{u.userJobTitle ? ` · ${u.userJobTitle}` : ""}
                              </p>
                            )}
                          </div>
                          <div className="flex items-center gap-2 flex-shrink-0">
                            {u.isAdminUser && (
                              <Badge variant="outline" className="text-xs border-red-300 text-red-500">Admin</Badge>
                            )}
                            <RiskBadge level={u.riskLevel} />
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Actions */}
                <div className="flex gap-3 pt-2">
                  {appDetail.homepageUrl && (
                    <Button size="sm" variant="outline" asChild>
                      <a href={appDetail.homepageUrl} target="_blank" rel="noopener noreferrer">
                        <ExternalLink className="h-4 w-4 mr-2" /> View App
                      </a>
                    </Button>
                  )}
                  <Button
                    size="sm"
                    variant={appDetail.isSanctioned ? "outline" : "default"}
                    className={appDetail.isSanctioned ? "text-orange-400 border-orange-400/30" : "bg-green-600 hover:bg-green-700 text-white"}
                    onClick={() => {
                      toggleSanctioned.mutate({ id: appDetail.id, isSanctioned: !appDetail.isSanctioned });
                      setSelectedApp(prev => prev ? { ...prev, isSanctioned: !prev.isSanctioned } : null);
                    }}
                    disabled={toggleSanctioned.isPending}
                  >
                    {appDetail.isSanctioned
                      ? <><EyeOff className="h-4 w-4 mr-2" /> Mark Unsanctioned</>
                      : <><Eye className="h-4 w-4 mr-2" /> Mark Sanctioned</>
                    }
                  </Button>
                </div>
              </div>
            </>
          )}
        </SheetContent>
      </Sheet>
    </div>
  );
}
