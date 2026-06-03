import { Switch, Route, Router as WouterRouter, Redirect, useLocation } from "wouter";
import { QueryClient, QueryClientProvider, QueryCache, MutationCache } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import { useAuth } from "@/hooks/useAuth";
import { AppLayout } from "@/components/layout/AppLayout";
import { Suspense, lazy } from "react";
import { attemptTokenRefresh } from "@/lib/auth";

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

function PublicRoute({ component: Component }: { component: React.ComponentType }) {
  const { isAuthenticated } = useAuth();
  if (isAuthenticated) return <Redirect to="/dashboard" />;
  return (
    <Suspense fallback={<PageLoader />}>
      <Component />
    </Suspense>
  );
}

function Router() {
  return (
    <Switch>
      {/* Public routes */}
      <Route path="/" component={() => <Redirect to="/dashboard" />} />
      <Route path="/login" component={() => <PublicRoute component={LoginPage} />} />
      <Route path="/register" component={() => <PublicRoute component={RegisterPage} />} />

      {/* Protected routes */}
      <Route path="/dashboard" component={() => <ProtectedRoute component={DashboardPage} />} />
      <Route path="/assets" component={() => <ProtectedRoute component={AssetsPage} />} />
      <Route path="/assets/:id" component={() => <ProtectedRoute component={AssetDetailPage} />} />
      <Route path="/asset-groups" component={() => <ProtectedRoute component={AssetGroupsPage} />} />
      <Route path="/findings" component={() => <ProtectedRoute component={FindingsPage} />} />
      <Route path="/findings/:id" component={() => <ProtectedRoute component={FindingDetailPage} />} />
      <Route path="/scans" component={() => <ProtectedRoute component={ScansPage} />} />
      <Route path="/compliance" component={() => <ProtectedRoute component={CompliancePage} />} />
      <Route path="/alerts" component={() => <ProtectedRoute component={AlertsPage} />} />
      <Route path="/risk" component={() => <ProtectedRoute component={RiskPage} />} />
      <Route path="/ai-copilot" component={() => <ProtectedRoute component={AiCopilotPage} />} />
      <Route path="/reports" component={() => <ProtectedRoute component={ReportsPage} />} />
      <Route path="/audit-logs" component={() => <ProtectedRoute component={AuditLogsPage} />} />
      <Route path="/settings/users" component={() => <ProtectedRoute component={UsersPage} />} />
      <Route path="/settings/tenant" component={() => <ProtectedRoute component={TenantSettingsPage} />} />
      <Route path="/tools" component={() => <ProtectedRoute component={SecurityToolsPage} />} />

      {/* Fallback */}
      <Route component={() => <Redirect to="/dashboard" />} />
    </Switch>
  );
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <WouterRouter base={import.meta.env.BASE_URL.replace(/\/$/, "")}>
          <Router />
        </WouterRouter>
        <Toaster />
      </TooltipProvider>
    </QueryClientProvider>
  );
}

export default App;
