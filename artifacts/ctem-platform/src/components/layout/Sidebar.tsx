import { Link, useLocation } from "wouter";
import { cn } from "@/lib/utils";
import {
  LayoutDashboard, Server, Layers, Radar, Bug, ShieldCheck,
  FileBarChart2, Bell, TrendingUp, Brain, ClipboardList,
  Users, Building2, ChevronRight, Shield, GitBranch, ScanSearch,
} from "lucide-react";

interface NavItem {
  label: string;
  href: string;
  icon: React.ElementType;
}

interface NavGroup {
  title: string;
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
  {
    title: "Admin",
    items: [
      { label: "Users", href: "/settings/users", icon: Users },
      { label: "Tenant", href: "/settings/tenant", icon: Building2 },
      { label: "Audit Logs", href: "/audit-logs", icon: ClipboardList },
    ],
  },
];

export function Sidebar() {
  const [location] = useLocation();

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

      {/* Navigation */}
      <nav className="flex-1 px-3 py-3 space-y-4">
        {navGroups.map((group) => (
          <div key={group.title}>
            <p className="px-2 mb-1 text-[10px] font-semibold uppercase tracking-widest text-muted-foreground/60">
              {group.title}
            </p>
            <div className="space-y-0.5">
              {group.items.map((item) => {
                const isActive = location === item.href || location.startsWith(item.href + "/");
                return (
                  <Link key={item.href} href={item.href}>
                    <div
                      className={cn(
                        "flex items-center gap-2.5 px-2.5 py-2 rounded-md text-sm cursor-pointer transition-all",
                        isActive
                          ? "bg-sidebar-accent text-foreground font-medium"
                          : "text-sidebar-foreground hover:bg-sidebar-accent/50 hover:text-foreground"
                      )}
                    >
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
