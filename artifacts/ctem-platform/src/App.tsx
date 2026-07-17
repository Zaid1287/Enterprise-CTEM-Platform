import { Switch, Route, Router as WouterRouter, Redirect, useLocation } from "wouter";
import { QueryClient, QueryClientProvider, QueryCache, MutationCache } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import { useAuth } from "@/hooks/useAuth";
import { AppLayout } from "@/components/layout/AppLayout";
import { Suspense, lazy, useEffect } from "react";
import { attemptTokenRefresh } from "@/lib/auth";
import { apiFetch } from "@/lib/apiFetch";
import { useToast } from "@/hooks/use-toast";

// Lazy-load pages for faster initial bundle
const LoginPage = lazy(() => import("@/pages/LoginPage"));
const RequestAccessPage = lazy(() => import("@/pages/RequestAccessPage"));
const AccessRequestsPage = lazy(() => import("@/pages/AccessRequestsPage"));
const DashboardPage = lazy(() => import("@/pages/DashboardPage"));
const AssetsPage = lazy(() => import("@/pages/AssetsPage"));
const AssetDetailPage = lazy(() => import("@/pages/AssetDetailPage"));
const AssetGroupsPage = lazy(() => import("@/pages/AssetGroupsPage"));
const FindingsPage = lazy(() => import("@/pages/FindingsPage"));
const FindingDetailPage = lazy(() => import("@/pages/FindingDetailPage"));
const FalsePositivesPage = lazy(() => import("@/pages/FalsePositivesPage"));
const ScansPage = lazy(() => import("@/pages/ScansPage"));
const CompliancePage = lazy(() => import("@/pages/CompliancePage"));
const AlertsPage = lazy(() => import("@/pages/AlertsPage"));
const RiskPage = lazy(() => import("@/pages/RiskPage"));
const AiCopilotPage = lazy(() => import("@/pages/AiCopilotPage"));
const ReportsPage = lazy(() => import("@/pages/ReportsPage"));
const AuditLogsPage = lazy(() => import("@/pages/AuditLogsPage"));
const UsersPage = lazy(() => import("@/pages/UsersPage"));
const TenantSettingsPage = lazy(() => import("@/pages/TenantSettingsPage"));
const SecurityToolsPage = lazy(() => import("@/pages/SecurityToolsPage"));
const ScanReportPage = lazy(() => import("@/pages/ScanReportPage"));
const ScanReportsPage = lazy(() => import("@/pages/ScanReportsPage"));
const PackagesPage = lazy(() => import("@/pages/PackagesPage"));
const MyClientsPage = lazy(() => import("@/pages/MyClientsPage"));
const TenantsPage = lazy(() => import("@/pages/TenantsPage"));
const TakedownsPage = lazy(() => import("@/pages/TakedownsPage"));
const AccountSettingsPage = lazy(() => import("@/pages/AccountSettingsPage"));
const ForgotPasswordPage = lazy(() => import("@/pages/ForgotPasswordPage"));
const AlertDetailPage = lazy(() => import("@/pages/AlertDetailPage"));
const PlatformSettingsPage = lazy(() => import("@/pages/PlatformSettingsPage"));
const BrandThreatPage = lazy(() => import("@/pages/BrandThreatPage"));
const BrandThreatDetailPage = lazy(() => import("@/pages/BrandThreatDetailPage"));
const ShadowItPage = lazy(() => import("@/pages/ShadowItPage"));
const ShadowItDashboardPage = lazy(() => import("@/pages/ShadowItDashboardPage"));
const ShadowItSaasPage = lazy(() => import("@/pages/ShadowItSaasPage"));
const ShadowItNetworkPage = lazy(() => import("@/pages/ShadowItNetworkPage"));
const ShadowItAlertsPage = lazy(() => import("@/pages/ShadowItAlertsPage"));
const AssetGroupDetailPage = lazy(() => import("@/pages/AssetGroupDetailPage"));
const AssetTopologyPage = lazy(() => import("@/pages/AssetTopologyPage"));
const QueueMonitorPage = lazy(() => import("@/pages/QueueMonitorPage"));
const CdnWhitelistPage = lazy(() => import("@/pages/CdnWhitelistPage"));
const DiscoveryPage = lazy(() => import("@/pages/DiscoveryPage"));
const ExposurePage = lazy(() => import("@/pages/ExposurePage"));
const AcceptInvitationPage = lazy(() => import("@/pages/AcceptInvitationPage"));
const AiMapperPage             = lazy(() => import("@/pages/AiMapperPage"));
const AiMapperScansPage        = lazy(() => import("@/pages/AiMapperScansPage"));
const AiMapperScanDetailPage   = lazy(() => import("@/pages/AiMapperScanDetailPage"));
const AiMapperEndpointsPage    = lazy(() => import("@/pages/AiMapperEndpointsPage"));
const AiMapperEndpointDetailPage = lazy(() => import("@/pages/AiMapperEndpointDetailPage"));
const AiMapperBomPage          = lazy(() => import("@/pages/AiMapperBomPage"));
const AiMapperAdminPage        = lazy(() => import("@/pages/AiMapperAdminPage"));
const AiMapperAmClientsPage         = lazy(() => import("@/pages/AiMapperAmClientsPage"));
const AiMapperClientViewPage        = lazy(() => import("@/pages/AiMapperClientViewPage"));
const AiMapperScanSchedulesPage     = lazy(() => import("@/pages/AiMapperScanSchedulesPage"));
const ScanOrchestrationPage  = lazy(() => import("@/pages/ScanOrchestrationPage"));
const ScanProxiesPage        = lazy(() => import("@/pages/ScanProxiesPage"));
const ScanFingerprintsPage   = lazy(() => import("@/pages/ScanFingerprintsPage"));
const OrchestratorConfigPage = lazy(() => import("@/pages/OrchestratorConfigPage"));
const ScanTelemetryPage      = lazy(() => import("@/pages/ScanTelemetryPage"));
const OrchestratorPage       = lazy(() => import("@/pages/OrchestratorPage"));

// Threat Intelligence pages
const ThreatIntelDashboardPage         = lazy(() => import("@/pages/ThreatIntelDashboardPage"));
const ThreatIntelIocsPage              = lazy(() => import("@/pages/ThreatIntelIocsPage"));
const ThreatIntelActorsPage            = lazy(() => import("@/pages/ThreatIntelActorsPage"));
const ThreatIntelActorDetailPage       = lazy(() => import("@/pages/ThreatIntelActorDetailPage"));
const ThreatIntelCampaignsPage         = lazy(() => import("@/pages/ThreatIntelCampaignsPage"));
const ThreatIntelMalwarePage           = lazy(() => import("@/pages/ThreatIntelMalwarePage"));
const ThreatIntelC2Page                = lazy(() => import("@/pages/ThreatIntelC2Page"));
const ThreatIntelCvesPage              = lazy(() => import("@/pages/ThreatIntelCvesPage"));
const ThreatIntelNewsPage              = lazy(() => import("@/pages/ThreatIntelNewsPage"));
const ThreatIntelDarkWebPage           = lazy(() => import("@/pages/ThreatIntelDarkWebPage"));
const ThreatIntelReportsPage           = lazy(() => import("@/pages/ThreatIntelReportsPage"));
const ThreatIntelCorrelationsPage      = lazy(() => import("@/pages/ThreatIntelCorrelationsPage"));
const ThreatIntelFeedsPage             = lazy(() => import("@/pages/ThreatIntelFeedsPage"));
const ThreatIntelUpgradePage           = lazy(() => import("@/pages/ThreatIntelUpgradePage"));

// TPRM pages
const TprmDashboardPage                = lazy(() => import("@/pages/TprmDashboardPage"));
const TprmVendorsPage                  = lazy(() => import("@/pages/TprmVendorsPage"));
const TprmVendorDetailPage             = lazy(() => import("@/pages/TprmVendorDetailPage"));
const TprmFourthPartyPage              = lazy(() => import("@/pages/TprmFourthPartyPage"));
const TprmSupplyChainPage              = lazy(() => import("@/pages/TprmSupplyChainPage"));
const TprmAdminPage                    = lazy(() => import("@/pages/TprmAdminPage"));
const TprmCompliancePage               = lazy(() => import("@/pages/TprmCompliancePage"));
const TprmQuestionnaireTemplatesPage   = lazy(() => import("@/pages/TprmQuestionnaireTemplatesPage"));
const TprmControlsManagerPage          = lazy(() => import("@/pages/TprmControlsManagerPage"));
const TprmVendorRespondPage            = lazy(() => import("@/pages/TprmVendorRespondPage"));
const TprmUpgradePage                  = lazy(() => import("@/pages/TprmUpgradePage"));

async function handle401(error: unknown) {
  if ((error as any)?.status === 401) {
    if (!useAuth.getState().isAuthenticated) return;
    const refreshed = await attemptTokenRefresh();
    if (refreshed) {
      queryClient.invalidateQueries();
    } else {
      useAuth.getState().logout();
    }
  }
}

const queryClient = new QueryClient({
  queryCache: new QueryCache({
    onError: handle401,
  }),
  mutationCache: new MutationCache({
    onError: handle401,
  }),
  defaultOptions: {
    queries: {
      retry: (failureCount, error) => {
        if ((error as any)?.status === 401) return false;
        return failureCount < 1;
      },
      staleTime: 30_000,
      refetchOnWindowFocus: false,
    },
  },
});

function PageLoader() {
  return (
    <div className="flex items-center justify-center h-64">
      <div className="w-5 h-5 border-2 border-primary border-t-transparent rounded-full animate-spin" />
    </div>
  );
}

function AiMapperBootstrap() {
  const { isAuthenticated, user, setAiMapperEnabled } = useAuth();
  useEffect(() => {
    if (!isAuthenticated) return;
    const role = user?.role;
    if (role === "admin" || role === "super_admin" || role === "account_manager") {
      setAiMapperEnabled(true);
      return;
    }
    apiFetch<{ aiMapperEnabled?: boolean }>("/api/auth/me")
      .then(data => setAiMapperEnabled(data.aiMapperEnabled ?? false))
      .catch(() => setAiMapperEnabled(false));
  }, [isAuthenticated]);
  return null;
}

function ProtectedRoute({ component: Component }: { component: React.ComponentType }) {
  const { isAuthenticated, user } = useAuth();
  const { toast } = useToast();
  const [location, navigate] = useLocation();

  const isExternalMember = EXTERNAL_ROLES.includes(user?.role ?? "");
  const isAllowed =
    !isExternalMember ||
    EXTERNAL_MEMBER_ALLOWED_PATHS.some(
      (p) => location === p || location.startsWith(p + "/")
    );

  useEffect(() => {
    if (isAuthenticated && isExternalMember && !isAllowed) {
      toast({
        title: "Access restricted",
        description: "Your account does not have permission to view that page.",
        variant: "destructive",
      });
      navigate("/assets");
    }
  }, [isAuthenticated, isExternalMember, isAllowed]);

  if (!isAuthenticated) return <Redirect to="/login" />;
  if (isExternalMember && !isAllowed) return null;
  return (
    <AppLayout>
      <Suspense fallback={<PageLoader />}>
        <Component />
      </Suspense>
    </AppLayout>
  );
}

function AdminRoute({ component: Component }: { component: React.ComponentType }) {
  const { isAuthenticated, user } = useAuth();
  if (!isAuthenticated) return <Redirect to="/login" />;
  const role = user?.role;
  if (role !== "super_admin" && role !== "admin") return <Redirect to="/dashboard" />;
  return (
    <AppLayout>
      <Suspense fallback={<PageLoader />}>
        <Component />
      </Suspense>
    </AppLayout>
  );
}

function SuperAdminRoute({ component: Component }: { component: React.ComponentType }) {
  const { isAuthenticated, user } = useAuth();
  if (!isAuthenticated) return <Redirect to="/login" />;
  if (user?.role !== "super_admin") return <Redirect to="/dashboard" />;
  return (
    <AppLayout>
      <Suspense fallback={<PageLoader />}>
        <Component />
      </Suspense>
    </AppLayout>
  );
}

function AiMapperRoute({ component: Component }: { component: React.ComponentType }) {
  const { isAuthenticated, user, aiMapperEnabled, aiMapperLoaded } = useAuth();
  const { toast } = useToast();
  const [, navigate] = useLocation();
  const isPrivileged = user?.role === "admin" || user?.role === "super_admin" || user?.role === "account_manager";

  useEffect(() => {
    if (!aiMapperLoaded) return;
    if (isAuthenticated && !isPrivileged && !aiMapperEnabled) {
      toast({
        title: "AI Mapper not enabled",
        description: "AI Mapper module is not enabled for your organization. Contact an administrator.",
        variant: "destructive",
      });
      navigate("/dashboard");
    }
  }, [isAuthenticated, aiMapperEnabled, aiMapperLoaded]);

  if (!isAuthenticated) return <Redirect to="/login" />;
  if (!aiMapperLoaded) return <AppLayout><PageLoader /></AppLayout>;
  if (!isPrivileged && !aiMapperEnabled) return null;
  return (
    <AppLayout>
      <Suspense fallback={<PageLoader />}>
        <Component />
      </Suspense>
    </AppLayout>
  );
}

function ThreatIntelBootstrap() {
  const { isAuthenticated, user, setThreatIntelEnabled } = useAuth();
  useEffect(() => {
    if (!isAuthenticated) return;
    const role = user?.role;
    if (role === "admin" || role === "super_admin" || role === "account_manager") {
      setThreatIntelEnabled(true);
      return;
    }
    apiFetch<{ isEnabled: boolean }>("/api/threat-intel/module")
      .then(d => setThreatIntelEnabled(d.isEnabled ?? false))
      .catch(() => setThreatIntelEnabled(false));
  }, [isAuthenticated, user?.role]);
  return null;
}

function ThreatIntelRoute({ component: Component }: { component: React.ComponentType }) {
  const { isAuthenticated, threatIntelEnabled, threatIntelLoaded, user } = useAuth();
  const [location] = useLocation();
  if (!isAuthenticated) return <Redirect to="/login" />;
  if (!threatIntelLoaded) return <AppLayout><PageLoader /></AppLayout>;
  const isPrivileged = user?.role === "admin" || user?.role === "super_admin" || user?.role === "account_manager";
  // Client role: only /threat-intel/correlations is accessible — redirect everything else
  if (user?.role === "client" && !location.startsWith("/threat-intel/correlations")) {
    return <Redirect to="/threat-intel/correlations" />;
  }
  if (!threatIntelEnabled && !isPrivileged) {
    return (
      <AppLayout>
        <Suspense fallback={<PageLoader />}>
          <ThreatIntelUpgradePage />
        </Suspense>
      </AppLayout>
    );
  }
  return (
    <AppLayout>
      <Suspense fallback={<PageLoader />}>
        <Component />
      </Suspense>
    </AppLayout>
  );
}

function ComplianceBootstrap() {
  const { isAuthenticated, user, setComplianceEnabled } = useAuth();
  useEffect(() => {
    if (!isAuthenticated) return;
    if (user?.role === "admin" || user?.role === "super_admin" || user?.role === "account_manager") {
      setComplianceEnabled(true);
      return;
    }
    apiFetch<{ isEnabled: boolean }>("/api/compliance/module")
      .then(d => setComplianceEnabled(d.isEnabled ?? false))
      .catch(() => setComplianceEnabled(false));
  }, [isAuthenticated, user?.role]);
  return null;
}

function ComplianceRoute({ component: Component }: { component: React.ComponentType }) {
  const { isAuthenticated, complianceEnabled, complianceLoaded, user } = useAuth();
  if (!isAuthenticated) return <Redirect to="/login" />;
  if (!complianceLoaded) return <AppLayout><PageLoader /></AppLayout>;
  const isPrivileged = user?.role === "admin" || user?.role === "super_admin" || user?.role === "account_manager";
  if (!complianceEnabled && !isPrivileged) {
    return (
      <AppLayout>
        <div className="flex flex-col items-center justify-center h-full gap-4 p-8 text-center">
          <div className="w-14 h-14 rounded-full bg-primary/10 flex items-center justify-center">
            <svg xmlns="http://www.w3.org/2000/svg" className="w-7 h-7 text-primary" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" /></svg>
          </div>
          <h2 className="text-lg font-semibold">Compliance Management</h2>
          <p className="text-sm text-muted-foreground max-w-sm">The Compliance Management module is not enabled for your account. Contact your administrator to enable it.</p>
        </div>
      </AppLayout>
    );
  }
  return (
    <AppLayout>
      <Suspense fallback={<PageLoader />}>
        <Component />
      </Suspense>
    </AppLayout>
  );
}

function TprmBootstrap() {
  const { isAuthenticated, setTprmEnabled, user } = useAuth();
  useEffect(() => {
    if (!isAuthenticated) return;
    // Admin, super_admin, and account_manager always have TPRM access — skip the API call
    if (user?.role === "admin" || user?.role === "super_admin" || user?.role === "account_manager") {
      setTprmEnabled(true);
      return;
    }
    apiFetch<{ isEnabled: boolean }>("/api/tprm/module")
      .then(d => setTprmEnabled(d.isEnabled ?? false))
      .catch(() => setTprmEnabled(false));
  }, [isAuthenticated, user?.role]);
  return null;
}

function TprmRoute({ component: Component }: { component: React.ComponentType }) {
  const { isAuthenticated, tprmEnabled, tprmLoaded, user } = useAuth();
  if (!isAuthenticated) return <Redirect to="/login" />;
  if (!tprmLoaded) return <AppLayout><PageLoader /></AppLayout>;
  const isPrivileged = user?.role === "admin" || user?.role === "super_admin" || user?.role === "account_manager";
  if (!tprmEnabled && !isPrivileged) {
    return (
      <AppLayout>
        <Suspense fallback={<PageLoader />}>
          <TprmUpgradePage />
        </Suspense>
      </AppLayout>
    );
  }
  return (
    <AppLayout>
      <Suspense fallback={<PageLoader />}>
        <Component />
      </Suspense>
    </AppLayout>
  );
}

const EXTERNAL_ROLES = ["vendor", "employee", "third_party"];

/** Routes external members (vendor / employee / third_party) are allowed to visit. */
const EXTERNAL_MEMBER_ALLOWED_PATHS = ["/assets", "/settings/account"];

function useDefaultPath() {
  const { user } = useAuth();
  return EXTERNAL_ROLES.includes(user?.role ?? "") ? "/assets" : "/dashboard";
}

function PublicRoute({ component: Component }: { component: React.ComponentType }) {
  const { isAuthenticated } = useAuth();
  const defaultPath = useDefaultPath();
  if (isAuthenticated) return <Redirect to={defaultPath} />;
  return (
    <Suspense fallback={<PageLoader />}>
      <Component />
    </Suspense>
  );
}

function Router() {
  const defaultPath = useDefaultPath();
  return (
    <Switch>
      {/* Public routes */}
      <Route path="/" component={() => <Redirect to={defaultPath} />} />
      <Route path="/login" component={() => <PublicRoute component={LoginPage} />} />
      <Route path="/register" component={() => <PublicRoute component={RequestAccessPage} />} />
      <Route path="/forgot-password" component={() => <PublicRoute component={ForgotPasswordPage} />} />
      <Route path="/accept-invitation" component={() => (
        <Suspense fallback={<PageLoader />}>
          <AcceptInvitationPage />
        </Suspense>
      )} />

      {/* Protected routes */}
      <Route path="/dashboard" component={() => <ProtectedRoute component={DashboardPage} />} />
      <Route path="/assets" component={() => <ProtectedRoute component={AssetsPage} />} />
      <Route path="/assets/:id" component={() => <ProtectedRoute component={AssetDetailPage} />} />
      <Route path="/asset-groups" component={() => <ProtectedRoute component={AssetGroupsPage} />} />
      <Route path="/asset-groups/:groupId" component={() => <ProtectedRoute component={AssetGroupDetailPage} />} />
      <Route path="/topology" component={() => <ProtectedRoute component={AssetTopologyPage} />} />
      <Route path="/findings" component={() => <ProtectedRoute component={FindingsPage} />} />
      <Route path="/findings/:id" component={() => <ProtectedRoute component={FindingDetailPage} />} />
      <Route path="/false-positives" component={() => <ProtectedRoute component={FalsePositivesPage} />} />
      <Route path="/scans" component={() => <ProtectedRoute component={ScansPage} />} />
      <Route path="/compliance" component={() => <ComplianceRoute component={CompliancePage} />} />
      <Route path="/alerts" component={() => <ProtectedRoute component={AlertsPage} />} />
      <Route path="/risk" component={() => <ProtectedRoute component={RiskPage} />} />
      <Route path="/ai-copilot" component={() => <ProtectedRoute component={AiCopilotPage} />} />
      <Route path="/ai-mapper" component={() => <AiMapperRoute component={AiMapperPage} />} />
      <Route path="/ai-mapper/scans" component={() => <AiMapperRoute component={AiMapperScansPage} />} />
      <Route path="/ai-mapper/scans/:id" component={() => <AiMapperRoute component={AiMapperScanDetailPage} />} />
      <Route path="/ai-mapper/endpoints" component={() => <AiMapperRoute component={AiMapperEndpointsPage} />} />
      <Route path="/ai-mapper/endpoints/:id" component={() => <AiMapperRoute component={AiMapperEndpointDetailPage} />} />
      <Route path="/ai-mapper/bom" component={() => <AiMapperRoute component={AiMapperBomPage} />} />
      <Route path="/ai-mapper/admin" component={() => <AiMapperRoute component={AiMapperAdminPage} />} />
      <Route path="/ai-mapper/clients" component={() => <AiMapperRoute component={AiMapperAmClientsPage} />} />
      <Route path="/ai-mapper/clients/:tenantId" component={() => <AiMapperRoute component={AiMapperClientViewPage} />} />
      <Route path="/ai-mapper/clients/:tenantId/scans/:scanId" component={() => <AiMapperRoute component={AiMapperClientViewPage} />} />
      <Route path="/ai-mapper/clients/:tenantId/endpoints/:id" component={() => <AiMapperRoute component={AiMapperClientViewPage} />} />
      <Route path="/ai-mapper/scan-schedules" component={() => <AiMapperRoute component={AiMapperScanSchedulesPage} />} />
      <Route path="/reports" component={() => <ProtectedRoute component={ReportsPage} />} />
      <Route path="/audit-logs" component={() => <ProtectedRoute component={AuditLogsPage} />} />
      <Route path="/settings/users" component={() => <ProtectedRoute component={UsersPage} />} />
      <Route path="/settings/tenant" component={() => <ProtectedRoute component={TenantSettingsPage} />} />
      <Route path="/tools" component={() => <ProtectedRoute component={SecurityToolsPage} />} />
      <Route path="/scan-reports" component={() => <ProtectedRoute component={ScanReportsPage} />} />
      <Route path="/scan-reports/:id" component={() => <ProtectedRoute component={ScanReportPage} />} />
      <Route path="/packages" component={() => <ProtectedRoute component={PackagesPage} />} />
      <Route path="/my-clients" component={() => <ProtectedRoute component={MyClientsPage} />} />
      <Route path="/tenants" component={() => <ProtectedRoute component={TenantsPage} />} />
      <Route path="/access-requests" component={() => <ProtectedRoute component={AccessRequestsPage} />} />
      <Route path="/takedowns" component={() => <ProtectedRoute component={TakedownsPage} />} />
      <Route path="/settings/account" component={() => <ProtectedRoute component={AccountSettingsPage} />} />
      <Route path="/alerts/:id" component={() => <ProtectedRoute component={AlertDetailPage} />} />
      <Route path="/settings/platform" component={() => <ProtectedRoute component={PlatformSettingsPage} />} />
      <Route path="/brand-threats" component={() => <ProtectedRoute component={BrandThreatPage} />} />
      <Route path="/brand-threats/:id" component={() => <ProtectedRoute component={BrandThreatDetailPage} />} />
      <Route path="/shadow-it" component={() => <ProtectedRoute component={ShadowItDashboardPage} />} />
      <Route path="/shadow-it/assets" component={() => <ProtectedRoute component={ShadowItPage} />} />
      <Route path="/shadow-it/saas" component={() => <ProtectedRoute component={ShadowItSaasPage} />} />
      <Route path="/shadow-it/network" component={() => <ProtectedRoute component={ShadowItNetworkPage} />} />
      <Route path="/shadow-it/alerts" component={() => <ProtectedRoute component={ShadowItAlertsPage} />} />
      <Route path="/queue-monitor" component={() => <ProtectedRoute component={QueueMonitorPage} />} />
      <Route path="/settings/cdn-whitelist" component={() => <ProtectedRoute component={CdnWhitelistPage} />} />
      <Route path="/discovery" component={() => <ProtectedRoute component={DiscoveryPage} />} />
      <Route path="/exposure" component={() => <ProtectedRoute component={ExposurePage} />} />
      <Route path="/scan-orchestration" component={() => <AdminRoute component={ScanOrchestrationPage} />} />
      <Route path="/settings/scan-proxies" component={() => <AdminRoute component={ScanProxiesPage} />} />
      <Route path="/settings/scan-fingerprints" component={() => <AdminRoute component={ScanFingerprintsPage} />} />
      <Route path="/settings/orchestrator-config" component={() => <AdminRoute component={OrchestratorConfigPage} />} />
      <Route path="/scan-telemetry" component={() => <AdminRoute component={ScanTelemetryPage} />} />
      <Route path="/settings/orchestration" component={() => <AdminRoute component={OrchestratorPage} />} />

      {/* Threat Intelligence routes */}
      <Route path="/threat-intel" component={() => <ThreatIntelRoute component={ThreatIntelDashboardPage} />} />
      <Route path="/threat-intel/iocs" component={() => <ThreatIntelRoute component={ThreatIntelIocsPage} />} />
      <Route path="/threat-intel/actors" component={() => <ThreatIntelRoute component={ThreatIntelActorsPage} />} />
      <Route path="/threat-intel/actors/:id" component={() => <ThreatIntelRoute component={ThreatIntelActorDetailPage} />} />
      <Route path="/threat-intel/campaigns" component={() => <ThreatIntelRoute component={ThreatIntelCampaignsPage} />} />
      <Route path="/threat-intel/malware" component={() => <ThreatIntelRoute component={ThreatIntelMalwarePage} />} />
      <Route path="/threat-intel/c2-servers" component={() => <ThreatIntelRoute component={ThreatIntelC2Page} />} />
      <Route path="/threat-intel/cves" component={() => <ThreatIntelRoute component={ThreatIntelCvesPage} />} />
      <Route path="/threat-intel/news" component={() => <ThreatIntelRoute component={ThreatIntelNewsPage} />} />
      <Route path="/threat-intel/dark-web" component={() => <ThreatIntelRoute component={ThreatIntelDarkWebPage} />} />
      <Route path="/threat-intel/reports" component={() => <ThreatIntelRoute component={ThreatIntelReportsPage} />} />
      <Route path="/threat-intel/correlations" component={() => <ThreatIntelRoute component={ThreatIntelCorrelationsPage} />} />
      <Route path="/threat-intel/feeds" component={() => <AdminRoute component={ThreatIntelFeedsPage} />} />
      <Route path="/threat-intel/upgrade" component={() => <ProtectedRoute component={ThreatIntelUpgradePage} />} />

      {/* TPRM — public respond route (no auth) */}
      <Route path="/tprm/respond/:token" component={() => (
        <Suspense fallback={<PageLoader />}>
          <TprmVendorRespondPage />
        </Suspense>
      )} />

      {/* TPRM — protected routes */}
      <Route path="/tprm" component={() => <TprmRoute component={TprmDashboardPage} />} />
      <Route path="/tprm/vendors/new" component={() => <TprmRoute component={TprmVendorsPage} />} />
      <Route path="/tprm/vendors/:id" component={() => <TprmRoute component={TprmVendorDetailPage} />} />
      <Route path="/tprm/vendors" component={() => <TprmRoute component={TprmVendorsPage} />} />
      <Route path="/tprm/fourth-parties" component={() => <TprmRoute component={TprmFourthPartyPage} />} />
      <Route path="/tprm/supply-chain" component={() => <TprmRoute component={TprmSupplyChainPage} />} />
      <Route path="/tprm/compliance/controls" component={() => <TprmRoute component={TprmControlsManagerPage} />} />
      <Route path="/tprm/compliance" component={() => <TprmRoute component={TprmCompliancePage} />} />
      <Route path="/tprm/questionnaire-templates" component={() => <TprmRoute component={TprmQuestionnaireTemplatesPage} />} />
      <Route path="/tprm/admin" component={() => <AdminRoute component={TprmAdminPage} />} />
      <Route path="/tprm/upgrade" component={() => <ProtectedRoute component={TprmUpgradePage} />} />

      {/* Fallback */}
      <Route component={() => <Redirect to={defaultPath} />} />
    </Switch>
  );
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <WouterRouter base={import.meta.env.BASE_URL.replace(/\/$/, "")}>
          <AiMapperBootstrap />
          <TprmBootstrap />
          <ThreatIntelBootstrap />
          <ComplianceBootstrap />
          <Router />
        </WouterRouter>
        <Toaster />
      </TooltipProvider>
    </QueryClientProvider>
  );
}

export default App;
