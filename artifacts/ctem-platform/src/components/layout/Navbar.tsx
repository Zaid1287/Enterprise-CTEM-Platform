import { useEffect, useRef, useState } from "react";
import { useLocation, Link } from "wouter";
import { Bell, LogOut, ChevronDown, User } from "lucide-react";
import { GlobalSearch } from "@/components/GlobalSearch";
import { useAuth } from "@/hooks/useAuth";
import { useListAlerts, useLogout } from "@workspace/api-client-react";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { getToken } from "@/lib/auth";

const BREADCRUMB_MAP: Record<string, string> = {
  "/dashboard": "Dashboard",
  "/assets": "Asset Inventory",
  "/asset-groups": "Asset Groups",
  "/scans": "Scans",
  "/findings": "Findings",
  "/compliance": "Compliance",
  "/reports": "Reports",
  "/alerts": "Alerts",
  "/risk": "Risk Scoring",
  "/ai-copilot": "AI Copilot",
  "/audit-logs": "Audit Logs",
  "/settings/users": "User Management",
  "/settings/tenant": "Tenant Settings",
  "/topology": "Asset Topology",
};

export function Navbar() {
  const [location, navigate] = useLocation();
  const { user, logout, isAuthenticated } = useAuth();
  const logoutMutation = useLogout();

  const { data: alerts } = useListAlerts();
  const baseUnread = Array.isArray(alerts) ? alerts.filter((a: any) => !a.isRead).length : 0;
  const [sseExtra, setSseExtra] = useState(0);
  const esRef = useRef<EventSource | null>(null);

  useEffect(() => {
    if (!isAuthenticated) return;
    const token = getToken();
    if (!token) return;

    const base = import.meta.env.BASE_URL.replace(/\/$/, "");
    const url = `${base}/api/alerts/stream?token=${encodeURIComponent(token)}`;
    const es = new EventSource(url);
    esRef.current = es;

    es.addEventListener("new-alert", () => {
      setSseExtra(n => n + 1);
    });

    es.onerror = () => {
      es.close();
      esRef.current = null;
    };

    return () => {
      es.close();
      esRef.current = null;
    };
  }, [isAuthenticated]);

  const unreadCount = baseUnread + sseExtra;

  const breadcrumb = Object.entries(BREADCRUMB_MAP).find(([path]) =>
    location === path || location.startsWith(path + "/")
  );

  const handleLogout = async () => {
    try { await logoutMutation.mutateAsync(); } catch {}
    logout();
    navigate("/login");
  };

  return (
    <header className="sticky top-0 z-10 flex items-center justify-between h-14 px-6 bg-background/95 backdrop-blur border-b border-border">
      <div className="flex items-center gap-1 text-sm text-muted-foreground">
        <span className="text-muted-foreground/50">Platform</span>
        {breadcrumb && (
          <>
            <span className="text-muted-foreground/30 mx-1">/</span>
            <span className="text-foreground font-medium">{breadcrumb[1]}</span>
          </>
        )}
      </div>

      <div className="flex items-center gap-2">
        <GlobalSearch />
        <Link href="/alerts">
          <Button variant="ghost" size="icon" className="relative">
            <Bell className="w-4 h-4" />
            {unreadCount > 0 && (
              <Badge
                className="absolute -top-1 -right-1 h-4 w-4 p-0 flex items-center justify-center text-[10px] bg-red-500 text-white border-0"
              >
                {unreadCount > 9 ? "9+" : unreadCount}
              </Badge>
            )}
          </Button>
        </Link>

        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="sm" className="flex items-center gap-2 h-8">
              <div className="w-6 h-6 rounded-full bg-primary/20 border border-primary/30 flex items-center justify-center">
                <User className="w-3 h-3 text-primary" />
              </div>
              <div className="text-left hidden sm:block">
                <p className="text-xs font-medium leading-none">{user?.firstName} {user?.lastName}</p>
                <p className="text-[10px] text-muted-foreground capitalize">{user?.role?.replace("_", " ")}</p>
              </div>
              <ChevronDown className="w-3 h-3 text-muted-foreground" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-48">
            <DropdownMenuLabel className="font-normal">
              <div className="flex flex-col space-y-1">
                <p className="text-sm font-medium">{user?.firstName} {user?.lastName}</p>
                <p className="text-xs text-muted-foreground truncate">{user?.email}</p>
              </div>
            </DropdownMenuLabel>
            <DropdownMenuSeparator />
            <DropdownMenuItem
              className="text-destructive focus:text-destructive cursor-pointer"
              onClick={handleLogout}
            >
              <LogOut className="w-4 h-4 mr-2" />
              Sign out
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
    </header>
  );
}
