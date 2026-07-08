import { Link, useLocation } from "wouter";
import { cn } from "@/lib/utils";
import { useAuth } from "@/hooks/useAuth";
import {
  LayoutDashboard, Server, Layers, Radar, Bug, ShieldCheck,
  FileBarChart2, Bell, TrendingUp, Brain, ClipboardList,
  Users, Building2, ChevronRight, GitBranch, ScanSearch,
  Package, UserCheck, ShieldOff, Settings, PanelLeftClose, PanelLeftOpen,
  ShieldAlert, Network, Activity, Shield, Globe2, Crosshair,
  Cpu, Radio, ScrollText, Fingerprint, Sliders, SlidersHorizontal,
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
      { label: "CDN Whitelist", href: "/settings/cdn-whitelist", icon: Shield, onlyFor: ["super_admin"] },
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
    onlyFor: ["client", "admin", "super_admin"],
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
    title: "Infrastructure",
    onlyFor: ["admin", "super_admin"],
    items: [
      { label: "Queue Monitor",    href: "/queue-monitor",           icon: Activity,     onlyFor: ["admin", "super_admin"] },
    ],
  },
  {
    title: "Scan Orchestration",
    onlyFor: ["admin", "super_admin"],
    items: [
      { label: "Orchestration",    href: "/settings/orchestration",      icon: SlidersHorizontal },
      { label: "Dashboard",        href: "/scan-orchestration",          icon: Cpu },
      { label: "Proxy Pool",       href: "/settings/scan-proxies",       icon: Radio,        onlyFor: ["super_admin"] },
      { label: "Fingerprints",     href: "/settings/scan-fingerprints",  icon: Fingerprint,  onlyFor: ["super_admin"] },
      { label: "Config",           href: "/settings/orchestrator-config", icon: Sliders,     onlyFor: ["super_admin"] },
      { label: "Telemetry Logs",   href: "/scan-telemetry",              icon: ScrollText },
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
      { label: "Users", href: "/settings/users", icon: Users, onlyFor: ["super_admin", "admin"] },
      { label: "Tenant Management", href: "/tenants", icon: Building2, onlyFor: ["super_admin", "admin"] },
      { label: "Access Requests", href: "/access-requests", icon: UserCheck, onlyFor: ["super_admin", "admin"] },
      { label: "Audit Logs", href: "/audit-logs", icon: ClipboardList, onlyFor: ["super_admin", "admin"] },
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
  const { user, aiMapperEnabled } = useAuth();
  const role = user?.role ?? "client";
  const [collapsed, setCollapsed] = useState(_collapsed);

  const toggle = () => {
    _collapsed = !collapsed;
    setCollapsed(!collapsed);
  };

  const isExternalMember = ["vendor", "employee", "third_party"].includes(role);

  // External members (vendor/employee/third_party) see only "My Assets"
  const externalGroups: NavGroup[] = isExternalMember ? [
    {
      title: "Assets",
      items: [{ label: "My Assets", href: "/assets", icon: Server }],
    },
  ] : [];

  const isAM = role === "account_manager";

  const aiMapperItems: NavItem[] = aiMapperEnabled ? [
    { label: "Overview",   href: "/ai-mapper",            icon: Globe2       },
    { label: "Endpoints",  href: "/ai-mapper/endpoints",  icon: Crosshair    },
    { label: "Scans",      href: "/ai-mapper/scans",      icon: Radar        },
    { label: "AI BOM",     href: "/ai-mapper/bom",        icon: ClipboardList },
    ...(isAM ? [{ label: "My Clients", href: "/ai-mapper/clients", icon: Users }] : []),
  ] : [];

  const aiMapperGroup: NavGroup | null = aiMapperItems.length > 0
    ? { title: "AI Mapper", items: aiMapperItems }
    : null;

  const filteredGroups = navGroups
    .filter(g => !g.onlyFor || g.onlyFor.includes(role))
    .map(g => ({
      ...g,
      items: g.items.filter(item => !item.onlyFor || item.onlyFor.includes(role)),
    }))
    .filter(g => g.items.length > 0);

  if (aiMapperGroup) {
    const brandIdx = filteredGroups.findIndex(g => g.title === "Brand Monitoring");
    filteredGroups.splice(brandIdx >= 0 ? brandIdx + 1 : filteredGroups.length, 0, aiMapperGroup);
  }

  const visibleGroups = isExternalMember ? externalGroups : filteredGroups;

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
