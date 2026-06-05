import { Link, useLocation } from "wouter";
import { cn } from "@/lib/utils";
import { useAuth } from "@/hooks/useAuth";
import {
  LayoutDashboard, Server, Layers, Radar, Bug, ShieldCheck,
  FileBarChart2, Bell, TrendingUp, Brain, ClipboardList,
  Users, Building2, ChevronRight, Shield, GitBranch, ScanSearch,
  Package, UserCheck, ShieldOff, Settings,
} from "lucide-react";

interface NavItem {
  label: string;
  href: string;
  icon: React.ElementType;
  /** Only shown if current user role is in this list. Omit = visible to all. */
  onlyFor?: string[];
}

interface NavGroup {
  title: string;
  /** Only shown if current user role is in this list. Omit = visible to all. */
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
  // ─── Platform-only (new) ────────────────────────────────────────
  {
    title: "Platform",
    onlyFor: ["super_admin"],
    items: [
      { label: "All Tenants", href: "/tenants", icon: Building2 },
      { label: "Packages", href: "/packages", icon: Package },
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
  // ─── Original CTEM modules — visible to all roles ───────────────
  {
    title: "Assets",
    items: [
      { label: "Asset Inventory", href: "/assets", icon: Server },
      { label: "Asset Groups", href: "/asset-groups", icon: Layers },
    ],
  },
  {
    title: "Security",
    items: [
      { label: "Scans", href: "/scans", icon: Radar },
      { label: "Findings", href: "/findings", icon: Bug },
      { label: "Risk Scoring", href: "/risk", icon: TrendingUp },
      { label: "Security Tools", href: "/tools", icon: GitBranch },
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
    title: "Intelligence",
    items: [
      { label: "AI Copilot", href: "/ai-copilot", icon: Brain },
    ],
  },
  // ─── Admin section ───────────────────────────────────────────────
  {
    title: "Admin",
    onlyFor: ["super_admin", "admin", "account_manager"],
    items: [
      { label: "Users", href: "/settings/users", icon: Users, onlyFor: ["super_admin", "admin", "account_manager"] },
      { label: "Tenant", href: "/settings/tenant", icon: Building2, onlyFor: ["admin"] },
      { label: "Audit Logs", href: "/audit-logs", icon: ClipboardList, onlyFor: ["super_admin", "admin", "account_manager"] },
    ],
  },
  // ─── Account settings — visible to all ──────────────────────────
  {
    title: "Account",
    items: [
      { label: "Settings", href: "/settings/account", icon: Settings },
    ],
  },
];

export function Sidebar() {
  const [location] = useLocation();
  const { user } = useAuth();
  const role = user?.role ?? "client";

  const visibleGroups = navGroups
    .filter(g => !g.onlyFor || g.onlyFor.includes(role))
    .map(g => ({
      ...g,
      items: g.items.filter(item => !item.onlyFor || item.onlyFor.includes(role)),
    }))
    .filter(g => g.items.length > 0);

  return (
    <aside className="flex flex-col w-60 shrink-0 bg-sidebar border-r border-sidebar-border h-screen sticky top-0 overflow-y-auto">
      {/* Logo */}
      <div className="flex items-center gap-2.5 px-5 py-4 border-b border-sidebar-border">
        <div className="flex items-center justify-center w-7 h-7 rounded-md bg-primary/20 border border-primary/30">
          <Shield className="w-4 h-4 text-primary" />
        </div>
        <div className="leading-none">
          <p className="text-sm font-semibold text-foreground tracking-tight">CTEM</p>
          <p className="text-[10px] text-muted-foreground uppercase tracking-widest">Platform</p>
        </div>
      </div>

      {/* Role badge */}
      <div className="px-5 py-2 border-b border-sidebar-border">
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

      {/* Navigation */}
      <nav className="flex-1 px-3 py-3 space-y-4">
        {visibleGroups.map((group) => (
          <div key={group.title}>
            <p className="px-2 mb-1 text-[10px] font-semibold uppercase tracking-widest text-muted-foreground/60">
              {group.title}
            </p>
            <div className="space-y-0.5">
              {group.items.map((item) => {
                const isActive = location === item.href || location.startsWith(item.href + "/");
                return (
                  <Link key={item.href} href={item.href}>
                    <div className={cn(
                      "flex items-center gap-2.5 px-2.5 py-2 rounded-md text-sm cursor-pointer transition-all",
                      isActive
                        ? "bg-sidebar-accent text-foreground font-medium"
                        : "text-sidebar-foreground hover:bg-sidebar-accent/50 hover:text-foreground"
                    )}>
                      <item.icon className={cn("w-4 h-4 shrink-0", isActive ? "text-primary" : "text-muted-foreground")} />
                      <span className="flex-1 truncate">{item.label}</span>
                      {isActive && <ChevronRight className="w-3 h-3 text-primary opacity-70" />}
                    </div>
                  </Link>
                );
              })}
            </div>
          </div>
        ))}
      </nav>

      {/* Footer */}
      <div className="px-3 py-3 border-t border-sidebar-border">
        <p className="px-2 text-[10px] text-muted-foreground/40">v1.0.0 — Enterprise Edition</p>
      </div>
    </aside>
  );
}
