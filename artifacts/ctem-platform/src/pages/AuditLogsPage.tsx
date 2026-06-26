import { useState } from "react";
import { useListAuditLogs, getListAuditLogsQueryKey } from "@workspace/api-client-react";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { capitalize, formatDateTime } from "@/lib/utils";
import { Lock, Monitor, Globe, Smartphone, Laptop, Server } from "lucide-react";
import { cn } from "@/lib/utils";

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
  const params = { action: actionFilter || undefined };
  const { data: logs, isLoading } = useListAuditLogs(params as any, {
    query: { queryKey: getListAuditLogsQueryKey(params as any) },
  });

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <div className="w-8 h-8 rounded-lg bg-primary/10 flex items-center justify-center shrink-0">
            <Lock className="w-4 h-4 text-primary" />
          </div>
          <div>
            <h1 className="text-lg font-semibold">Audit Logs</h1>
            <p className="text-xs text-muted-foreground">Immutable record of all platform activity — logins, changes, and access events</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Input
            value={actionFilter}
            onChange={e => setActionFilter(e.target.value)}
            placeholder="Filter by action (e.g. login, create)…"
            className="w-56 h-8 text-xs"
          />
        </div>
      </div>

      <div className="bg-card border border-border rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-muted/20">
                <th className="text-left px-4 py-3 text-[10px] font-semibold text-muted-foreground uppercase tracking-wide whitespace-nowrap">Timestamp</th>
                <th className="text-left px-4 py-3 text-[10px] font-semibold text-muted-foreground uppercase tracking-wide">User</th>
                <th className="text-left px-4 py-3 text-[10px] font-semibold text-muted-foreground uppercase tracking-wide">Action</th>
                <th className="text-left px-4 py-3 text-[10px] font-semibold text-muted-foreground uppercase tracking-wide">Resource</th>
                <th className="text-left px-4 py-3 text-[10px] font-semibold text-muted-foreground uppercase tracking-wide">IP Address</th>
                <th className="text-left px-4 py-3 text-[10px] font-semibold text-muted-foreground uppercase tracking-wide">Device</th>
                <th className="text-left px-4 py-3 text-[10px] font-semibold text-muted-foreground uppercase tracking-wide">Browser</th>
                <th className="text-left px-4 py-3 text-[10px] font-semibold text-muted-foreground uppercase tracking-wide">OS</th>
                <th className="text-left px-4 py-3 text-[10px] font-semibold text-muted-foreground uppercase tracking-wide">Details</th>
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
              {!isLoading && (logs as any[] ?? []).map((log: any) => (
                <tr key={log.id} className="border-b border-border/40 hover:bg-accent/20 transition-colors group">
                  <td className="px-4 py-2.5 text-[11px] text-muted-foreground font-mono whitespace-nowrap">
                    {formatDateTime(log.createdAt)}
                  </td>
                  <td className="px-4 py-2.5">
                    <div className="flex flex-col gap-0.5">
                      <span className="text-xs font-medium">{log.userEmail ?? `User #${log.userId}`}</span>
                    </div>
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
                  <td className="px-4 py-2.5 text-xs text-muted-foreground max-w-[200px] truncate" title={log.details ?? ""}>
                    {log.details ?? <span className="text-muted-foreground/40">—</span>}
                  </td>
                </tr>
              ))}
              {!isLoading && (logs as any[] ?? []).length === 0 && (
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
      </div>
    </div>
  );
}
