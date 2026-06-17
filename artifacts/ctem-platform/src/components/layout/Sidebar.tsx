import { Link, useLocation } from "wouter";
import { cn } from "@/lib/utils";
import { useAuth } from "@/hooks/useAuth";
import {
  LayoutDashboard, Server, Layers, Radar, Bug, ShieldCheck,
  FileBarChart2, Bell, TrendingUp, Brain, ClipboardList,
  Users, Building2, ChevronRight, GitBranch, ScanSearch,
  Package, UserCheck, ShieldOff, Settings, PanelLeftClose, PanelLeftOpen,
  ShieldAlert, Network,
} from "lucide-react";
import { useState } from "react";

const BASE = import.meta.env.BASE_URL.replace(/\/$/, "");

interface NavItem {
  label: string;
  href: string;
  icon: React.ElementType;
  onlyFor?: string[];
}

interface NavGroup {
  title: string;
  onlyFor?: string[];
  items: NavItem[];
}

const navGroups: NavGroup[] = [
  {
    title: "Overview",
    items: [
      { label: "Dashboard", href: "/dashboard", icon: LayoutDashboard },
    ],
  },
  {
    title: "Platform",
    onlyFor: ["super_admin"],
    items: [
      { label: "All Tenants", href: "/tenants", icon: Building2 },
      { label: "Packages", href: "/packages", icon: Package },
      { label: "Platform Settings", href: "/settings/platform", icon: Settings, onlyFor: ["super_admin"] },
    ],
  },
  {
    title: "Clients",
    onlyFor: ["account_manager"],
    items: [
      { label: "My Clients", href: "/my-clients", icon: UserCheck },
    ],
  },
  {
    title: "Protection",
    onlyFor: ["client", "admin"],
    items: [
      { label: "Takedown Requests", href: "/takedowns", icon: ShieldOff },
    ],
  },
  {
    title: "Assets",
    items: [
      { label: "Asset Inventory", href: "/assets", icon: Server },
      { label: "Asset Groups", href: "/asset-groups", icon: Layers },
      { label: "Asset Topology", href: "/topology", icon: Network },
    ],
  },
  {
    title: "Security",
    items: [
      { label: "Scans", href: "/scans", icon: Radar },
      { label: "Findings", href: "/findings", icon: Bug },
      { label: "Risk Scoring", href: "/risk", icon: TrendingUp },
      { label: "Security Tools", href: "/tools", icon: GitBranch, onlyFor: ["admin", "super_admin", "account_manager"] },
      { label: "Scan Reports", href: "/scan-reports", icon: ScanSearch },
    ],
  },
  {
    title: "Governance",
    items: [
      { label: "Compliance", href: "/compliance", icon: ShieldCheck },
      { label: "Reports", href: "/reports", icon: FileBarChart2 },
      { label: "Alerts", href: "/alerts", icon: Bell },
    ],
  },
  {
    title: "Brand Monitoring",
    items: [
      { label: "Brand Threat Monitor", href: "/brand-threats", icon: ShieldAlert },
    ],
  },
  {
    title: "Intelligence",
    items: [
      { label: "AI Copilot", href: "/ai-copilot", icon: Brain },
    ],
  },
  {
    title: "Admin",
    onlyFor: ["super_admin", "admin", "account_manager"],
    items: [
      { label: "Users", href: "/settings/users", icon: Users, onlyFor: ["super_admin", "admin", "account_manager"] },
      { label: "Tenant", href: "/settings/tenant", icon: Building2, onlyFor: ["admin"] },
      { label: "Audit Logs", href: "/audit-logs", icon: ClipboardList, onlyFor: ["super_admin", "admin", "account_manager"] },
    ],
  },
  {
    title: "Account",
    items: [
      { label: "Settings", href: "/settings/account", icon: Settings },
    ],
  },
];

let _collapsed = false;

export function Sidebar() {
  const [location] = useLocation();
  const { user } = useAuth();
  const role = user?.role ?? "client";
  const [collapsed, setCollapsed] = useState(_collapsed);

  const toggle = () => {
    _collapsed = !collapsed;
    setCollapsed(!collapsed);
  };

  const visibleGroups = navGroups
    .filter(g => !g.onlyFor || g.onlyFor.includes(role))
    .map(g => ({
      ...g,
      items: g.items.filter(item => !item.onlyFor || item.onlyFor.includes(role)),
    }))
    .filter(g => g.items.length > 0);

  return (
    <aside
      className={cn(
        "flex flex-col shrink-0 bg-sidebar border-r border-sidebar-border h-screen sticky top-0 overflow-y-auto transition-all duration-200",
        collapsed ? "w-14" : "w-60",
      )}
    >
      {/* Logo + toggle */}
      <div className={cn(
        "flex items-center border-b border-sidebar-border",
        collapsed ? "justify-center px-0 py-4" : "gap-2.5 px-4 py-4 justify-between",
      )}>
        {!collapsed && (
          <div className="flex items-center gap-2.5 min-w-0">
            <img
              src={`${BASE}/sentinelware-logo.png`}
              alt="Sentinelware"
              className="h-6 w-auto object-contain shrink-0"
              onError={e => { (e.target as HTMLImageElement).style.display = "none"; }}
            />
          </div>
        )}
        {collapsed && (
          <div className="flex items-center justify-center w-7 h-7">
            <img
              src={`${BASE}/sentinelware-logo.png`}
              alt="SW"
              className="w-6 h-6 object-contain"
              onError={e => { (e.target as HTMLImageElement).style.display = "none"; }}
            />
          </div>
        )}
        <button
          onClick={toggle}
          className={cn(
            "flex items-center justify-center w-6 h-6 rounded hover:bg-sidebar-accent/60 text-muted-foreground hover:text-foreground transition-colors shrink-0",
            collapsed && "hidden",
          )}
          title={collapsed ? "Expand sidebar" : "Collapse sidebar"}
        >
          <PanelLeftClose className="w-4 h-4" />
        </button>
      </div>

      {/* Expand button when collapsed */}
      {collapsed && (
        <button
          onClick={toggle}
          className="flex items-center justify-center py-2 hover:bg-sidebar-accent/60 text-muted-foreground hover:text-foreground transition-colors"
          title="Expand sidebar"
        >
          <PanelLeftOpen className="w-4 h-4" />
        </button>
      )}

      {/* Role badge — hidden for client role */}
      {!collapsed && role !== "client" && (
        <div className="px-4 py-2 border-b border-sidebar-border">
          <span className={cn(
            "text-[10px] px-2 py-0.5 rounded font-semibold uppercase tracking-wider",
            role === "super_admin"     ? "bg-purple-500/20 text-purple-400 border border-purple-500/30" :
            role === "account_manager" ? "bg-blue-500/20   text-blue-400   border border-blue-500/30"   :
            role === "admin"           ? "bg-green-500/20  text-green-400  border border-green-500/30"   :
                                         "bg-muted text-muted-foreground border border-border"
          )}>
            {role.replace(/_/g, " ")}
          </span>
        </div>
      )}

      {/* Navigation */}
      <nav className={cn("flex-1 py-3 space-y-4", collapsed ? "px-1.5" : "px-3")}>
        {visibleGroups.map((group) => (
          <div key={group.title}>
            {!collapsed && (
              <p className="px-2 mb-1 text-[10px] font-semibold uppercase tracking-widest text-muted-foreground/60">
                {group.title}
              </p>
            )}
            <div className="space-y-0.5">
              {group.items.map((item) => {
                const isActive = location === item.href || location.startsWith(item.href + "/");
                return (
                  <Link key={item.href} href={item.href}>
                    <div
                      title={collapsed ? item.label : undefined}
                      className={cn(
                        "flex items-center gap-2.5 rounded-md text-sm cursor-pointer transition-all",
                        collapsed ? "justify-center px-0 py-2.5" : "px-2.5 py-2",
                        isActive
                          ? "bg-sidebar-accent text-foreground font-medium"
                          : "text-sidebar-foreground hover:bg-sidebar-accent/50 hover:text-foreground",
                      )}
                    >
                      <item.icon className={cn("w-4 h-4 shrink-0", isActive ? "text-primary" : "text-muted-foreground")} />
                      {!collapsed && <span className="flex-1 truncate">{item.label}</span>}
                      {!collapsed && isActive && <ChevronRight className="w-3 h-3 text-primary opacity-70" />}
                    </div>
                  </Link>
                );
              })}
            </div>
          </div>
        ))}
      </nav>
    </aside>
  );
}
