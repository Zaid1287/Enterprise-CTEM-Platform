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
const RegisterPage = lazy(() => import("@/pages/RegisterPage"));
const DashboardPage = lazy(() => import("@/pages/DashboardPage"));
const AssetsPage = lazy(() => import("@/pages/AssetsPage"));
const AssetDetailPage = lazy(() => import("@/pages/AssetDetailPage"));
const AssetGroupsPage = lazy(() => import("@/pages/AssetGroupsPage"));
const FindingsPage = lazy(() => import("@/pages/FindingsPage"));
const FindingDetailPage = lazy(() => import("@/pages/FindingDetailPage"));
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
const AiMapperAmClientsPage    = lazy(() => import("@/pages/AiMapperAmClientsPage"));
const AiMapperClientViewPage   = lazy(() => import("@/pages/AiMapperClientViewPage"));

async function handle401(error: unknown) {
  if ((error as any)?.status === 401) {
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
  const { isAuthenticated, setAiMapperEnabled } = useAuth();
  useEffect(() => {
    if (!isAuthenticated) return;
    apiFetch<{ aiMapperEnabled?: boolean }>("/api/auth/me")
      .then(data => setAiMapperEnabled(data.aiMapperEnabled ?? false))
      .catch(() => setAiMapperEnabled(false));
  }, [isAuthenticated]);
  return null;
}

function ProtectedRoute({ component: Component }: { component: React.ComponentType }) {
  const { isAuthenticated } = useAuth();
  if (!isAuthenticated) return <Redirect to="/login" />;
  return (
    <AppLayout>
      <Suspense fallback={<PageLoader />}>
        <Component />
      </Suspense>
    </AppLayout>
  );
}

function AiMapperRoute({ component: Component }: { component: React.ComponentType }) {
  const { isAuthenticated, aiMapperEnabled, aiMapperLoaded } = useAuth();
  const { toast } = useToast();
  const [, navigate] = useLocation();

  useEffect(() => {
    if (!aiMapperLoaded) return;
    if (isAuthenticated && !aiMapperEnabled) {
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
  if (!aiMapperEnabled) return null;
  return (
    <AppLayout>
      <Suspense fallback={<PageLoader />}>
        <Component />
      </Suspense>
    </AppLayout>
  );
}

const EXTERNAL_ROLES = ["vendor", "employee", "third_party"];

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
      <Route path="/register" component={() => <PublicRoute component={RegisterPage} />} />
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
      <Route path="/scans" component={() => <ProtectedRoute component={ScansPage} />} />
      <Route path="/compliance" component={() => <ProtectedRoute component={CompliancePage} />} />
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
      <Route path="/takedowns" component={() => <ProtectedRoute component={TakedownsPage} />} />
      <Route path="/settings/account" component={() => <ProtectedRoute component={AccountSettingsPage} />} />
      <Route path="/alerts/:id" component={() => <ProtectedRoute component={AlertDetailPage} />} />
      <Route path="/settings/platform" component={() => <ProtectedRoute component={PlatformSettingsPage} />} />
      <Route path="/brand-threats" component={() => <ProtectedRoute component={BrandThreatPage} />} />
      <Route path="/brand-threats/:id" component={() => <ProtectedRoute component={BrandThreatDetailPage} />} />
      <Route path="/queue-monitor" component={() => <ProtectedRoute component={QueueMonitorPage} />} />
      <Route path="/settings/cdn-whitelist" component={() => <ProtectedRoute component={CdnWhitelistPage} />} />
      <Route path="/discovery" component={() => <ProtectedRoute component={DiscoveryPage} />} />
      <Route path="/exposure" component={() => <ProtectedRoute component={ExposurePage} />} />

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
          <Router />
        </WouterRouter>
        <Toaster />
      </TooltipProvider>
    </QueryClientProvider>
  );
}

export default App;
