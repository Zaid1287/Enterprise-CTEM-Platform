import { useState } from "react";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { Button } from "@/components/ui/button";
import { formatDateTime } from "@/lib/utils";
import {
  Lock, Monitor, Globe, Smartphone, Laptop, Server,
  ChevronLeft, ChevronRight, ChevronsLeft, ChevronsRight,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { useQuery } from "@tanstack/react-query";
import { apiFetch } from "@/lib/apiFetch";

const BASE = import.meta.env.BASE_URL.replace(/\/$/, "");
const PAGE_SIZE = 50;

interface AuditLog {
  id: number;
  userId: number | null;
  userEmail: string | null;
  action: string;
  resource: string;
  resourceId: string | null;
  details: string | null;
  ipAddress: string | null;
  device: string | null;
  browser: string | null;
  os: string | null;
  createdAt: string;
}

interface AuditLogsResponse {
  data: AuditLog[];
  total: number;
  page: number;
  limit: number;
  totalPages: number;
}

function timeAgo(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  const s = Math.floor(diff / 1000);
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  const d = Math.floor(h / 24);
  if (d < 30) return `${d}d ago`;
  const mo = Math.floor(d / 30);
  if (mo < 12) return `${mo}mo ago`;
  return `${Math.floor(mo / 12)}y ago`;
}

function DeviceIcon({ device }: { device?: string | null }) {
  const d = (device ?? "").toLowerCase();
  if (d.includes("mobile") || d.includes("phone")) return <Smartphone className="w-3 h-3 text-muted-foreground shrink-0" />;
  if (d.includes("tablet")) return <Monitor className="w-3 h-3 text-muted-foreground shrink-0" />;
  if (d.includes("desktop") || d.includes("laptop")) return <Laptop className="w-3 h-3 text-muted-foreground shrink-0" />;
  if (d.includes("bot") || d.includes("server")) return <Server className="w-3 h-3 text-muted-foreground shrink-0" />;
  return <Globe className="w-3 h-3 text-muted-foreground shrink-0" />;
}

const ACTION_COLOR: Record<string, string> = {
  login:            "bg-green-500/10 text-green-400 border-green-500/20",
  logout:           "bg-slate-500/10 text-slate-400 border-slate-500/20",
  create:           "bg-blue-500/10 text-blue-400 border-blue-500/20",
  update:           "bg-amber-500/10 text-amber-400 border-amber-500/20",
  delete:           "bg-red-500/10 text-red-400 border-red-500/20",
  register:         "bg-purple-500/10 text-purple-400 border-purple-500/20",
  password_change:  "bg-orange-500/10 text-orange-400 border-orange-500/20",
  "2fa_enabled":    "bg-teal-500/10 text-teal-400 border-teal-500/20",
  "2fa_disabled":   "bg-rose-500/10 text-rose-400 border-rose-500/20",
};

function ActionBadge({ action }: { action: string }) {
  const cls = ACTION_COLOR[action] ?? "bg-muted text-muted-foreground border-border";
  return (
    <span className={cn("text-[10px] px-2 py-0.5 rounded border font-mono font-semibold uppercase tracking-wide", cls)}>
      {action.replace(/_/g, " ")}
    </span>
  );
}

export default function AuditLogsPage() {
  const [actionFilter, setActionFilter] = useState("");
  const [page, setPage] = useState(1);

  const { data: resp, isLoading } = useQuery<AuditLogsResponse>({
    queryKey: ["audit-logs", actionFilter, page],
    queryFn: () => {
      const params = new URLSearchParams({ page: String(page), limit: String(PAGE_SIZE) });
      if (actionFilter) params.set("action", actionFilter);
      return apiFetch<AuditLogsResponse>(`${BASE}/api/audit-logs?${params}`);
    },
    placeholderData: (prev) => prev,
  });

  const logs = resp?.data ?? [];
  const total = resp?.total ?? 0;
  const totalPages = resp?.totalPages ?? 1;

  const goTo = (p: number) => setPage(Math.max(1, Math.min(p, totalPages)));

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <div className="w-8 h-8 rounded-lg bg-primary/10 flex items-center justify-center shrink-0">
            <Lock className="w-4 h-4 text-primary" />
          </div>
          <div>
            <h1 className="text-lg font-semibold">Audit Logs</h1>
            <p className="text-xs text-muted-foreground">
              Immutable record of all platform activity — logins, changes, and access events
              {total > 0 && <span className="ml-1 text-muted-foreground/60">({total.toLocaleString()} total)</span>}
            </p>
          </div>
        </div>
        <Input
          value={actionFilter}
          onChange={e => { setActionFilter(e.target.value); setPage(1); }}
          placeholder="Filter by action (e.g. login, create)…"
          className="w-56 h-8 text-xs"
        />
      </div>

      {/* Table */}
      <div className="bg-card border border-border rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-muted/20">
                <th className="text-left px-4 py-3 text-[10px] font-semibold text-muted-foreground uppercase tracking-wide whitespace-nowrap">Timestamp</th>
                <th className="text-left px-4 py-3 text-[10px] font-semibold text-muted-foreground uppercase tracking-wide whitespace-nowrap">When</th>
                <th className="text-left px-4 py-3 text-[10px] font-semibold text-muted-foreground uppercase tracking-wide">User</th>
                <th className="text-left px-4 py-3 text-[10px] font-semibold text-muted-foreground uppercase tracking-wide">Action</th>
                <th className="text-left px-4 py-3 text-[10px] font-semibold text-muted-foreground uppercase tracking-wide">Resource</th>
                <th className="text-left px-4 py-3 text-[10px] font-semibold text-muted-foreground uppercase tracking-wide">IP Address</th>
                <th className="text-left px-4 py-3 text-[10px] font-semibold text-muted-foreground uppercase tracking-wide">Device</th>
                <th className="text-left px-4 py-3 text-[10px] font-semibold text-muted-foreground uppercase tracking-wide">Browser</th>
                <th className="text-left px-4 py-3 text-[10px] font-semibold text-muted-foreground uppercase tracking-wide">OS</th>
              </tr>
            </thead>
            <tbody>
              {isLoading && [...Array(10)].map((_, i) => (
                <tr key={i} className="border-b border-border/40">
                  {[...Array(9)].map((_, j) => (
                    <td key={j} className="px-4 py-3">
                      <Skeleton className="h-3.5 w-full" />
                    </td>
                  ))}
                </tr>
              ))}
              {!isLoading && logs.map((log) => (
                <tr key={log.id} className="border-b border-border/40 hover:bg-accent/20 transition-colors">
                  <td className="px-4 py-2.5 text-[11px] text-muted-foreground font-mono whitespace-nowrap">
                    {formatDateTime(log.createdAt)}
                  </td>
                  <td className="px-4 py-2.5 text-[11px] text-muted-foreground/70 whitespace-nowrap">
                    {timeAgo(log.createdAt)}
                  </td>
                  <td className="px-4 py-2.5">
                    <span className="text-xs font-medium">{log.userEmail ?? `User #${log.userId}`}</span>
                  </td>
                  <td className="px-4 py-2.5">
                    <ActionBadge action={log.action} />
                  </td>
                  <td className="px-4 py-2.5 text-xs text-muted-foreground">
                    <span className="capitalize">{log.resource}</span>
                    {log.resourceId ? <span className="text-muted-foreground/50"> #{log.resourceId}</span> : null}
                  </td>
                  <td className="px-4 py-2.5 text-[11px] font-mono text-muted-foreground whitespace-nowrap">
                    {log.ipAddress
                      ? <span className="bg-muted/40 px-1.5 py-0.5 rounded text-foreground/80">{log.ipAddress}</span>
                      : <span className="text-muted-foreground/40">—</span>
                    }
                  </td>
                  <td className="px-4 py-2.5">
                    <div className="flex items-center gap-1.5">
                      <DeviceIcon device={log.device} />
                      <span className="text-xs text-muted-foreground capitalize">
                        {log.device ?? <span className="text-muted-foreground/40">—</span>}
                      </span>
                    </div>
                  </td>
                  <td className="px-4 py-2.5 text-xs text-muted-foreground">
                    {log.browser ?? <span className="text-muted-foreground/40">—</span>}
                  </td>
                  <td className="px-4 py-2.5 text-xs text-muted-foreground">
                    {log.os ?? <span className="text-muted-foreground/40">—</span>}
                  </td>
                </tr>
              ))}
              {!isLoading && logs.length === 0 && (
                <tr>
                  <td colSpan={9} className="px-4 py-12 text-center text-sm text-muted-foreground">
                    <Lock className="w-6 h-6 mx-auto mb-2 text-muted-foreground/40" />
                    No audit logs found.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination footer */}
        {totalPages > 1 && (
          <div className="flex items-center justify-between px-4 py-3 border-t border-border bg-muted/10">
            <p className="text-xs text-muted-foreground">
              Showing <span className="font-medium text-foreground">{((page - 1) * PAGE_SIZE) + 1}–{Math.min(page * PAGE_SIZE, total)}</span> of{" "}
              <span className="font-medium text-foreground">{total.toLocaleString()}</span> entries
            </p>
            <div className="flex items-center gap-1">
              <Button variant="outline" size="sm" className="h-7 w-7 p-0" onClick={() => goTo(1)} disabled={page === 1}>
                <ChevronsLeft className="w-3.5 h-3.5" />
              </Button>
              <Button variant="outline" size="sm" className="h-7 w-7 p-0" onClick={() => goTo(page - 1)} disabled={page === 1}>
                <ChevronLeft className="w-3.5 h-3.5" />
              </Button>
              <div className="flex items-center gap-1 mx-1">
                {Array.from({ length: Math.min(5, totalPages) }, (_, i) => {
                  let p: number;
                  if (totalPages <= 5) p = i + 1;
                  else if (page <= 3) p = i + 1;
                  else if (page >= totalPages - 2) p = totalPages - 4 + i;
                  else p = page - 2 + i;
                  return (
                    <button
                      key={p}
                      onClick={() => goTo(p)}
                      className={cn(
                        "h-7 min-w-[28px] px-2 rounded text-xs font-medium transition-colors",
                        p === page
                          ? "bg-primary text-primary-foreground"
                          : "text-muted-foreground hover:bg-accent hover:text-foreground",
                      )}
                    >
                      {p}
                    </button>
                  );
                })}
              </div>
              <Button variant="outline" size="sm" className="h-7 w-7 p-0" onClick={() => goTo(page + 1)} disabled={page === totalPages}>
                <ChevronRight className="w-3.5 h-3.5" />
              </Button>
              <Button variant="outline" size="sm" className="h-7 w-7 p-0" onClick={() => goTo(totalPages)} disabled={page === totalPages}>
                <ChevronsRight className="w-3.5 h-3.5" />
              </Button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
