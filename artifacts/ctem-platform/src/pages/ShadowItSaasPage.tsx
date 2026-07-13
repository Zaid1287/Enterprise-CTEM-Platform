import { useState } from "react";
import { apiFetch } from "@/lib/apiFetch";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Card, CardContent, CardHeader, CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter,
} from "@/components/ui/dialog";
import {
  Tabs, TabsContent, TabsList, TabsTrigger,
} from "@/components/ui/tabs";
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from "@/components/ui/table";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import {
  Shield, RefreshCw, Plus, Trash2, Settings2, Users, AlertTriangle,
  CheckCircle2, XCircle, Clock, ChevronRight, ExternalLink, Eye, EyeOff,
} from "lucide-react";
import {
  Sheet, SheetContent, SheetHeader, SheetTitle,
} from "@/components/ui/sheet";

// ── Types ─────────────────────────────────────────────────────────────────────

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
  riskScore: number; riskLevel: string; riskFactors: Array<{ scope: string; level: string; reason: string }> | null;
  userCount: number; isAdminConsented: boolean; isSanctioned: boolean; status: string;
  firstDiscoveredAt: string; users?: OauthUser[];
}

interface OauthUser {
  id: number; userEmail: string; userDisplayName: string; userDepartment: string | null;
  userJobTitle: string | null; scopesGranted: string[] | null; riskLevel: string; isAdminUser: boolean;
}

// ── Constants ─────────────────────────────────────────────────────────────────

const PROVIDER_META: Record<string, { label: string; color: string; abbr: string; setupSteps: string[] }> = {
  google_workspace: {
    label: "Google Workspace",
    color: "#4285F4",
    abbr: "G",
    setupSteps: [
      "1. Create a Service Account in Google Cloud Console",
      "2. Enable Domain-Wide Delegation on the service account",
      "3. In Google Admin Console → Security → API Controls → Domain-wide delegation, add the service account with scopes: admin.directory.user.readonly, admin.directory.user.security",
      "4. Download the JSON key file and save its content as platform setting: shadow_it_google_sa_json",
      "5. Enter the super admin email below (used for impersonation)",
    ],
  },
  microsoft_graph: {
    label: "Microsoft Entra ID",
    color: "#00A4EF",
    abbr: "M",
    setupSteps: [
      "1. Register an App in Azure AD (App registrations → New registration)",
      "2. Add Application permissions: Application.Read.All, User.Read.All, DelegatedPermissionGrant.ReadWrite.All",
      "3. Grant Admin Consent for the permissions",
      "4. Create a Client Secret and save it as platform setting: shadow_it_azure_client_secret",
      "5. Enter the Tenant ID, Client ID below",
    ],
  },
  okta: {
    label: "Okta",
    color: "#007DC1",
    abbr: "O",
    setupSteps: [
      "1. In Okta Admin Console → Security → API → Tokens, create a new API token",
      "2. Save the token as platform setting: shadow_it_okta_api_token",
      "3. Enter your Okta domain (e.g., mycompany.okta.com) below",
    ],
  },
};

const RISK_COLORS: Record<string, string> = {
  critical: "#ef4444", high: "#f97316", medium: "#eab308", low: "#22c55e",
};

const PERM_LABELS: Record<string, string> = {
  canReadFiles: "Read Files", canWriteFiles: "Write Files",
  canReadEmail: "Read Email", canSendEmail: "Send Email",
  canReadCalendar: "Read Calendar", canManageUsers: "Manage Users",
  hasAdminAccess: "Admin Access",
};

// ── Main Component ────────────────────────────────────────────────────────────

export default function ShadowItSaasPage() {
  const qc = useQueryClient();
  const [syncing, setSyncing] = useState<number | null>(null);
  const [showAddIdp, setShowAddIdp] = useState(false);
  const [addProvider, setAddProvider] = useState("google_workspace");
  const [addForm, setAddForm] = useState<Record<string, string>>({});
  const [selectedApp, setSelectedApp] = useState<OauthApp | null>(null);
  const [filterRisk, setFilterRisk] = useState("all");
  const [filterProvider, setFilterProvider] = useState("all");
  const [filterSanctioned, setFilterSanctioned] = useState("all");

  const idpQ = useQuery<IdpConnection[]>({
    queryKey: ["shadow-it-idp"],
    queryFn: () => apiFetch("/api/shadow-it/idp-connections"),
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
  });

  const appDetailQ = useQuery<OauthApp>({
    queryKey: ["shadow-it-oauth-app", selectedApp?.id],
    queryFn: () => apiFetch(`/api/shadow-it/oauth-apps/${selectedApp!.id}`),
    enabled: !!selectedApp,
  });

  const addIdpMut = useMutation({
    mutationFn: (data: Record<string, string>) =>
      apiFetch("/api/shadow-it/idp-connections", { method: "POST", body: JSON.stringify(data) }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["shadow-it-idp"] }); setShowAddIdp(false); setAddForm({}); },
  });

  const deleteIdpMut = useMutation({
    mutationFn: (id: number) => apiFetch(`/api/shadow-it/idp-connections/${id}`, { method: "DELETE" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["shadow-it-idp"] }),
  });

  const toggleSanctioned = useMutation({
    mutationFn: ({ id, isSanctioned }: { id: number; isSanctioned: boolean }) =>
      apiFetch(`/api/shadow-it/oauth-apps/${id}`, { method: "PATCH", body: JSON.stringify({ isSanctioned }) }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["shadow-it-oauth-apps"] }),
  });

  const syncConn = async (id: number) => {
    setSyncing(id);
    try {
      await apiFetch(`/api/shadow-it/idp-connections/${id}/sync`, { method: "POST" });
      await new Promise(r => setTimeout(r, 2000));
      qc.invalidateQueries({ queryKey: ["shadow-it-idp"] });
      qc.invalidateQueries({ queryKey: ["shadow-it-oauth-apps"] });
    } catch { /* ignore */ }
    setSyncing(null);
  };

  const appDetail = appDetailQ.data ?? selectedApp;

  return (
    <>
      <div className="p-6 space-y-6 max-w-7xl mx-auto">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold flex items-center gap-2">
              <Shield className="h-6 w-6 text-purple-500" />
              SaaS &amp; OAuth Discovery
            </h1>
            <p className="text-muted-foreground text-sm mt-1">
              IdP integrations · OAuth scope risk · employee attribution
            </p>
          </div>
          <Button onClick={() => setShowAddIdp(true)}>
            <Plus className="h-4 w-4 mr-2" /> Connect IdP
          </Button>
        </div>

        <Tabs defaultValue="connections">
          <TabsList>
            <TabsTrigger value="connections">IdP Connections</TabsTrigger>
            <TabsTrigger value="apps">OAuth Apps ({appsQ.data?.total ?? 0})</TabsTrigger>
          </TabsList>

          {/* ── Connections Tab ── */}
          <TabsContent value="connections" className="space-y-4 mt-4">
            {idpQ.isLoading && <p className="text-sm text-muted-foreground">Loading…</p>}
            {idpQ.data?.length === 0 && (
              <Card>
                <CardContent className="py-10 text-center">
                  <Shield className="h-10 w-10 text-muted-foreground mx-auto mb-3" />
                  <p className="font-medium">No IdP connections configured</p>
                  <p className="text-sm text-muted-foreground mt-1">Connect Google Workspace, Microsoft Entra ID, or Okta to start discovering shadow OAuth apps.</p>
                  <Button className="mt-4" onClick={() => setShowAddIdp(true)}>
                    <Plus className="h-4 w-4 mr-2" /> Connect your first IdP
                  </Button>
                </CardContent>
              </Card>
            )}
            {idpQ.data?.map(conn => {
              const meta = PROVIDER_META[conn.provider];
              return (
                <Card key={conn.id}>
                  <CardContent className="p-4">
                    <div className="flex items-start justify-between">
                      <div className="flex items-center gap-4">
                        <div className="h-10 w-10 rounded-full flex items-center justify-center text-white font-bold text-sm"
                          style={{ background: meta?.color ?? "#888" }}>
                          {meta?.abbr ?? conn.provider[0].toUpperCase()}
                        </div>
                        <div>
                          <p className="font-medium">{conn.displayName}</p>
                          <p className="text-sm text-muted-foreground">{meta?.label ?? conn.provider}</p>
                          {conn.configEmail && <p className="text-xs text-muted-foreground">Admin: {conn.configEmail}</p>}
                          {conn.configDomain && <p className="text-xs text-muted-foreground">Domain: {conn.configDomain}</p>}
                          {conn.configTenantId && <p className="text-xs text-muted-foreground">Tenant: {conn.configTenantId}</p>}
                        </div>
                      </div>
                      <div className="flex items-center gap-3">
                        <div className="text-right text-sm">
                          <p>{conn.syncedApps} apps · {conn.syncedUsers} users</p>
                          <div className="flex items-center gap-1 justify-end mt-1">
                            {conn.lastSyncStatus === "success" && <><CheckCircle2 className="h-3 w-3 text-green-500" /><span className="text-xs text-green-600">Synced</span></>}
                            {conn.lastSyncStatus === "failed" && <><XCircle className="h-3 w-3 text-red-500" /><span className="text-xs text-red-600">Failed</span></>}
                            {conn.lastSyncStatus === "never" && <><Clock className="h-3 w-3 text-muted-foreground" /><span className="text-xs text-muted-foreground">Never synced</span></>}
                          </div>
                          {conn.lastSyncError && <p className="text-xs text-red-500 mt-1 max-w-xs truncate" title={conn.lastSyncError}>{conn.lastSyncError}</p>}
                        </div>
                        <Button size="sm" variant="outline" disabled={syncing === conn.id} onClick={() => syncConn(conn.id)}>
                          <RefreshCw className={`h-4 w-4 ${syncing === conn.id ? "animate-spin" : ""}`} />
                          <span className="ml-1">{syncing === conn.id ? "Syncing…" : "Sync"}</span>
                        </Button>
                        <Button size="sm" variant="ghost" className="text-red-500"
                          onClick={() => { if (confirm("Delete this IdP connection?")) deleteIdpMut.mutate(conn.id); }}>
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </div>
                    </div>

                    {conn.lastSyncStatus === "never" && (
                      <div className="mt-4 p-3 rounded-lg bg-muted/50 text-xs space-y-1">
                        <p className="font-medium text-sm mb-2">Setup checklist for {meta?.label}:</p>
                        {meta?.setupSteps.map((step, i) => <p key={i}>{step}</p>)}
                      </div>
                    )}
                  </CardContent>
                </Card>
              );
            })}
          </TabsContent>

          {/* ── OAuth Apps Tab ── */}
          <TabsContent value="apps" className="space-y-4 mt-4">
            {/* Filters */}
            <div className="flex gap-3 flex-wrap">
              <Select value={filterProvider} onValueChange={setFilterProvider}>
                <SelectTrigger className="w-48"><SelectValue placeholder="All providers" /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All providers</SelectItem>
                  <SelectItem value="google_workspace">Google Workspace</SelectItem>
                  <SelectItem value="microsoft_graph">Microsoft Entra ID</SelectItem>
                  <SelectItem value="okta">Okta</SelectItem>
                </SelectContent>
              </Select>
              <Select value={filterRisk} onValueChange={setFilterRisk}>
                <SelectTrigger className="w-40"><SelectValue placeholder="All risk levels" /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All risk levels</SelectItem>
                  <SelectItem value="critical">Critical</SelectItem>
                  <SelectItem value="high">High</SelectItem>
                  <SelectItem value="medium">Medium</SelectItem>
                  <SelectItem value="low">Low</SelectItem>
                </SelectContent>
              </Select>
              <Select value={filterSanctioned} onValueChange={setFilterSanctioned}>
                <SelectTrigger className="w-44"><SelectValue placeholder="All apps" /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All apps</SelectItem>
                  <SelectItem value="false">Unsanctioned only</SelectItem>
                  <SelectItem value="true">Sanctioned only</SelectItem>
                </SelectContent>
              </Select>
            </div>

            {appsQ.data?.items.length === 0 && (
              <Card>
                <CardContent className="py-10 text-center">
                  <p className="text-sm text-muted-foreground">No OAuth apps discovered yet. Sync an IdP connection to start.</p>
                </CardContent>
              </Card>
            )}

            <div className="rounded-lg border overflow-hidden">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>App</TableHead>
                    <TableHead>Provider</TableHead>
                    <TableHead>Type</TableHead>
                    <TableHead>Risk</TableHead>
                    <TableHead>Users</TableHead>
                    <TableHead>Permissions</TableHead>
                    <TableHead>Sanctioned</TableHead>
                    <TableHead></TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {appsQ.data?.items.map(app => (
                    <TableRow key={app.id} className="cursor-pointer hover:bg-muted/50" onClick={() => setSelectedApp(app)}>
                      <TableCell>
                        <div className="flex items-center gap-2">
                          {app.logoUrl
                            ? <img src={app.logoUrl} className="h-6 w-6 rounded" alt="" onError={e => { (e.target as HTMLImageElement).style.display = "none"; }} />
                            : <div className="h-6 w-6 rounded bg-muted flex items-center justify-center text-xs font-bold">{app.displayName.slice(0, 2).toUpperCase()}</div>
                          }
                          <div>
                            <p className="font-medium text-sm">{app.displayName}</p>
                            {app.publisherDomain && <p className="text-xs text-muted-foreground">{app.publisherDomain}</p>}
                          </div>
                        </div>
                      </TableCell>
                      <TableCell>
                        <span className="text-xs">{PROVIDER_META[app.provider]?.label ?? app.provider}</span>
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline" className="text-xs uppercase">{app.appType}</Badge>
                      </TableCell>
                      <TableCell>
                        <Badge className="text-xs text-white capitalize" style={{ background: RISK_COLORS[app.riskLevel] ?? "#888" }}>
                          {app.riskLevel}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center gap-1">
                          <Users className="h-3 w-3 text-muted-foreground" />
                          <span className="text-sm">{app.userCount}</span>
                        </div>
                      </TableCell>
                      <TableCell>
                        <div className="flex gap-1 flex-wrap max-w-40">
                          {app.permissionSummary && Object.entries(app.permissionSummary)
                            .filter(([k, v]) => v && k !== "scopeCount" && k !== "highestRisk")
                            .slice(0, 2)
                            .map(([k]) => (
                              <span key={k} className="text-xs bg-muted px-1 rounded">{PERM_LABELS[k] ?? k}</span>
                            ))}
                          {(app.scopes?.length ?? 0) > 0 && <span className="text-xs text-muted-foreground">{app.scopes!.length} scope{app.scopes!.length !== 1 ? "s" : ""}</span>}
                        </div>
                      </TableCell>
                      <TableCell onClick={e => e.stopPropagation()}>
                        <Button
                          size="sm"
                          variant={app.isSanctioned ? "default" : "outline"}
                          className={`text-xs h-7 ${app.isSanctioned ? "bg-green-600 hover:bg-green-700" : ""}`}
                          onClick={() => toggleSanctioned.mutate({ id: app.id, isSanctioned: !app.isSanctioned })}
                        >
                          {app.isSanctioned ? <><CheckCircle2 className="h-3 w-3 mr-1" />Sanctioned</> : <><AlertTriangle className="h-3 w-3 mr-1" />Unsanctioned</>}
                        </Button>
                      </TableCell>
                      <TableCell>
                        <ChevronRight className="h-4 w-4 text-muted-foreground" />
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          </TabsContent>
        </Tabs>
      </div>

      {/* ── Add IdP Dialog ── */}
      <Dialog open={showAddIdp} onOpenChange={setShowAddIdp}>
        <DialogContent className="max-w-xl">
          <DialogHeader>
            <DialogTitle>Connect Identity Provider</DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            <div>
              <Label>Provider</Label>
              <Select value={addProvider} onValueChange={setAddProvider}>
                <SelectTrigger className="mt-1"><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="google_workspace">Google Workspace</SelectItem>
                  <SelectItem value="microsoft_graph">Microsoft Entra ID</SelectItem>
                  <SelectItem value="okta">Okta</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div>
              <Label>Connection Name</Label>
              <Input className="mt-1" placeholder={`My ${PROVIDER_META[addProvider]?.label} connection`}
                value={addForm.displayName ?? ""}
                onChange={e => setAddForm(f => ({ ...f, displayName: e.target.value }))} />
            </div>

            {addProvider === "google_workspace" && (
              <div>
                <Label>Super Admin Email</Label>
                <Input className="mt-1" placeholder="admin@company.com"
                  value={addForm.configEmail ?? ""}
                  onChange={e => setAddForm(f => ({ ...f, configEmail: e.target.value }))} />
                <p className="text-xs text-muted-foreground mt-1">
                  The service account JSON must be saved as platform setting key <code>shadow_it_google_sa_json</code>
                </p>
              </div>
            )}

            {addProvider === "microsoft_graph" && (
              <>
                <div>
                  <Label>Azure Tenant ID</Label>
                  <Input className="mt-1" placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                    value={addForm.configTenantId ?? ""}
                    onChange={e => setAddForm(f => ({ ...f, configTenantId: e.target.value }))} />
                </div>
                <div>
                  <Label>App Registration Client ID</Label>
                  <Input className="mt-1" placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                    value={addForm.configClientId ?? ""}
                    onChange={e => setAddForm(f => ({ ...f, configClientId: e.target.value }))} />
                </div>
                <p className="text-xs text-muted-foreground">
                  Client secret must be saved as platform setting key <code>shadow_it_azure_client_secret</code>
                </p>
              </>
            )}

            {addProvider === "okta" && (
              <div>
                <Label>Okta Domain</Label>
                <Input className="mt-1" placeholder="mycompany.okta.com"
                  value={addForm.configDomain ?? ""}
                  onChange={e => setAddForm(f => ({ ...f, configDomain: e.target.value }))} />
                <p className="text-xs text-muted-foreground mt-1">
                  API token must be saved as platform setting key <code>shadow_it_okta_api_token</code>
                </p>
              </div>
            )}

            <div className="rounded-lg bg-muted/50 p-3 text-xs space-y-1">
              <p className="font-medium">Setup steps:</p>
              {PROVIDER_META[addProvider]?.setupSteps.map((s, i) => <p key={i}>{s}</p>)}
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowAddIdp(false)}>Cancel</Button>
            <Button
              disabled={!addForm.displayName || addIdpMut.isPending}
              onClick={() => addIdpMut.mutate({ ...addForm, provider: addProvider })}
            >
              {addIdpMut.isPending ? "Connecting…" : "Connect"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* ── App Detail Drawer ── */}
      <Sheet open={!!selectedApp} onOpenChange={open => !open && setSelectedApp(null)}>
        <SheetContent className="w-full sm:max-w-2xl overflow-y-auto">
          {appDetail && (
            <>
              <SheetHeader>
                <SheetTitle className="flex items-center gap-3">
                  {appDetail.logoUrl
                    ? <img src={appDetail.logoUrl} className="h-8 w-8 rounded" alt="" />
                    : <div className="h-8 w-8 rounded bg-muted flex items-center justify-center text-sm font-bold">{appDetail.displayName.slice(0, 2).toUpperCase()}</div>
                  }
                  {appDetail.displayName}
                </SheetTitle>
              </SheetHeader>

              <div className="mt-6 space-y-6">
                {/* Risk Summary */}
                <div className="grid grid-cols-3 gap-3">
                  <div className="rounded-lg border p-3 text-center">
                    <p className="text-xs text-muted-foreground">Risk Level</p>
                    <Badge className="mt-1 text-white capitalize" style={{ background: RISK_COLORS[appDetail.riskLevel] ?? "#888" }}>
                      {appDetail.riskLevel}
                    </Badge>
                  </div>
                  <div className="rounded-lg border p-3 text-center">
                    <p className="text-xs text-muted-foreground">Users</p>
                    <p className="text-xl font-bold">{appDetail.userCount}</p>
                  </div>
                  <div className="rounded-lg border p-3 text-center">
                    <p className="text-xs text-muted-foreground">Status</p>
                    <p className="text-sm font-medium capitalize">{appDetail.isSanctioned ? "✓ Sanctioned" : "⚠ Unsanctioned"}</p>
                  </div>
                </div>

                {/* Permissions */}
                {appDetail.permissionSummary && (
                  <div>
                    <p className="font-medium text-sm mb-2">Effective Permissions</p>
                    <div className="grid grid-cols-2 gap-2">
                      {Object.entries(appDetail.permissionSummary)
                        .filter(([k]) => !["scopeCount", "highestRisk"].includes(k))
                        .map(([k, v]) => (
                          <div key={k} className={`flex items-center gap-2 p-2 rounded text-xs ${v ? "bg-red-50 text-red-700 dark:bg-red-950 dark:text-red-300" : "bg-muted text-muted-foreground"}`}>
                            {v ? <AlertTriangle className="h-3 w-3" /> : <CheckCircle2 className="h-3 w-3" />}
                            {PERM_LABELS[k] ?? k}
                          </div>
                        ))}
                    </div>
                  </div>
                )}

                {/* Scope Breakdown */}
                {appDetail.riskFactors && appDetail.riskFactors.length > 0 && (
                  <div>
                    <p className="font-medium text-sm mb-2">Scope Risk Breakdown</p>
                    <div className="space-y-1 max-h-48 overflow-y-auto">
                      {appDetail.riskFactors.map((f, i) => (
                        <div key={i} className="flex items-start justify-between gap-2 text-xs p-2 rounded border">
                          <code className="text-xs flex-1 break-all">{f.scope}</code>
                          <div className="text-right shrink-0">
                            <Badge className="text-xs text-white capitalize" style={{ background: RISK_COLORS[f.level] ?? "#888" }}>{f.level}</Badge>
                            <p className="text-muted-foreground mt-0.5">{f.reason}</p>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Users with access */}
                {appDetail.users && appDetail.users.length > 0 && (
                  <div>
                    <p className="font-medium text-sm mb-2">Employees with Access ({appDetail.users.length})</p>
                    <div className="space-y-1 max-h-60 overflow-y-auto">
                      {appDetail.users.map(u => (
                        <div key={u.id} className="flex items-center justify-between p-2 rounded border text-sm">
                          <div>
                            <p className="font-medium">{u.userDisplayName}</p>
                            <p className="text-xs text-muted-foreground">{u.userEmail}</p>
                            {u.userDepartment && <p className="text-xs text-muted-foreground">{u.userDepartment}{u.userJobTitle ? ` · ${u.userJobTitle}` : ""}</p>}
                          </div>
                          <div className="flex items-center gap-2">
                            {u.isAdminUser && <Badge variant="outline" className="text-xs border-red-300 text-red-600">Admin</Badge>}
                            <Badge className="text-xs text-white capitalize" style={{ background: RISK_COLORS[u.riskLevel] ?? "#888" }}>{u.riskLevel}</Badge>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Actions */}
                <div className="flex gap-2">
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
                    onClick={() => toggleSanctioned.mutate({ id: appDetail.id, isSanctioned: !appDetail.isSanctioned })}
                  >
                    {appDetail.isSanctioned ? <><EyeOff className="h-4 w-4 mr-2" />Mark Unsanctioned</> : <><Eye className="h-4 w-4 mr-2" />Mark Sanctioned</>}
                  </Button>
                </div>
              </div>
            </>
          )}
        </SheetContent>
      </Sheet>
    </>
  );
}
