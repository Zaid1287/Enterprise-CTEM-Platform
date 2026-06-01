import { useState } from "react";
import { useListAuditLogs, getListAuditLogsQueryKey } from "@workspace/api-client-react";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { capitalize, formatDateTime } from "@/lib/utils";
import { Lock } from "lucide-react";

export default function AuditLogsPage() {
  const [actionFilter, setActionFilter] = useState("");
  const params = { action: actionFilter || undefined };
  const { data: logs, isLoading } = useListAuditLogs(params as any, {
    query: { queryKey: getListAuditLogsQueryKey(params as any) },
  });

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <Lock className="w-4 h-4 text-muted-foreground" />
        <div>
          <h1 className="text-lg font-semibold">Audit Logs</h1>
          <p className="text-sm text-muted-foreground">Immutable record of all platform activity</p>
        </div>
      </div>

      <div className="flex gap-2">
        <Input
          value={actionFilter}
          onChange={e => setActionFilter(e.target.value)}
          placeholder="Filter by action..."
          className="max-w-xs h-8 text-sm"
        />
      </div>

      <div className="bg-card border border-border rounded-xl overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border">
              <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Timestamp</th>
              <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">User</th>
              <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Action</th>
              <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Resource</th>
              <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Details</th>
              <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">IP Address</th>
            </tr>
          </thead>
          <tbody>
            {isLoading && [...Array(8)].map((_, i) => (
              <tr key={i} className="border-b border-border/50">
                {[...Array(6)].map((_, j) => <td key={j} className="px-4 py-3"><Skeleton className="h-4" /></td>)}
              </tr>
            ))}
            {!isLoading && (logs as any[] ?? []).map((log: any) => (
              <tr key={log.id} className="border-b border-border/50 hover:bg-accent/20">
                <td className="px-4 py-2.5 text-xs text-muted-foreground font-mono">{formatDateTime(log.createdAt)}</td>
                <td className="px-4 py-2.5 text-xs">{log.userEmail ?? `#${log.userId}`}</td>
                <td className="px-4 py-2.5">
                  <span className="text-xs bg-accent/50 px-2 py-0.5 rounded font-mono">{log.action}</span>
                </td>
                <td className="px-4 py-2.5 text-xs text-muted-foreground">
                  {log.resource}{log.resourceId ? ` #${log.resourceId}` : ""}
                </td>
                <td className="px-4 py-2.5 text-xs text-muted-foreground">{log.details ?? "—"}</td>
                <td className="px-4 py-2.5 text-xs text-muted-foreground font-mono">{log.ipAddress ?? "—"}</td>
              </tr>
            ))}
            {!isLoading && (logs as any[] ?? []).length === 0 && (
              <tr><td colSpan={6} className="px-4 py-8 text-center text-sm text-muted-foreground">No audit logs found.</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
