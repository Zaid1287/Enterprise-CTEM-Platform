import { useState } from "react";
import { Link } from "wouter";
import {
  useListFindings, getListFindingsQueryKey,
} from "@workspace/api-client-react";
import { Search, Filter, ExternalLink } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { cn, severityBgColor, statusBadgeClass, capitalize, formatDate } from "@/lib/utils";

const STATUSES = ["open", "in_progress", "accepted_risk", "false_positive", "mitigated"];
const SEVERITIES = ["critical", "high", "medium", "low", "info"];

export default function FindingsPage() {
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("");

  const params = {
    search: search || undefined,
    severity: severity || undefined,
    status: status || undefined,
  };

  const { data: findings, isLoading } = useListFindings(params as any, {
    query: { queryKey: getListFindingsQueryKey(params as any) },
  });

  const list = findings as any[] ?? [];

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold">Vulnerability Findings</h1>
          <p className="text-sm text-muted-foreground">{list.length} findings across all assets</p>
        </div>
      </div>

      {/* Filters */}
      <div className="flex gap-2 flex-wrap">
        <div className="relative flex-1 min-w-48 max-w-xs">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
          <Input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search findings..." className="pl-8 h-8 text-sm" />
        </div>
        <Select value={severity || "_all_"} onValueChange={(v) => setSeverity(v === "_all_" ? "" : v)}>
          <SelectTrigger className="w-32 h-8 text-sm"><SelectValue placeholder="Severity" /></SelectTrigger>
          <SelectContent>
            <SelectItem value="_all_">All</SelectItem>
            {SEVERITIES.map(s => <SelectItem key={s} value={s}>{capitalize(s)}</SelectItem>)}
          </SelectContent>
        </Select>
        <Select value={status || "_all_"} onValueChange={(v) => setStatus(v === "_all_" ? "" : v)}>
          <SelectTrigger className="w-36 h-8 text-sm"><SelectValue placeholder="Status" /></SelectTrigger>
          <SelectContent>
            <SelectItem value="_all_">All</SelectItem>
            {STATUSES.map(s => <SelectItem key={s} value={s}>{capitalize(s)}</SelectItem>)}
          </SelectContent>
        </Select>
        <Button variant="outline" size="sm" onClick={() => { setSeverity(""); setStatus(""); setSearch(""); }}>Clear</Button>
      </div>

      <div className="bg-card border border-border rounded-xl overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border">
              <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Title</th>
              <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Asset</th>
              <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Severity</th>
              <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">CVE</th>
              <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">CVSS</th>
              <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Status</th>
              <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Found</th>
              <th className="px-4 py-2.5" />
            </tr>
          </thead>
          <tbody>
            {isLoading && [...Array(5)].map((_, i) => (
              <tr key={i} className="border-b border-border/50">
                {[...Array(8)].map((_, j) => <td key={j} className="px-4 py-3"><Skeleton className="h-4" /></td>)}
              </tr>
            ))}
            {!isLoading && list.map((f: any) => (
              <tr key={f.id} className="border-b border-border/50 hover:bg-accent/30 transition-colors">
                <td className="px-4 py-2.5 max-w-xs">
                  <div className="flex items-center gap-1.5">
                    {f.isKev && <span className="text-[10px] bg-red-500/20 text-red-400 border border-red-500/30 px-1.5 py-0.5 rounded font-bold shrink-0">KEV</span>}
                    <Link href={`/findings/${f.id}`}>
                      <span className="font-medium text-primary hover:underline cursor-pointer line-clamp-1">{f.title}</span>
                    </Link>
                  </div>
                </td>
                <td className="px-4 py-2.5 text-xs text-muted-foreground">{f.assetName ?? "—"}</td>
                <td className="px-4 py-2.5">
                  <span className={cn("text-xs px-2 py-0.5 rounded-md font-medium", severityBgColor(f.severity))}>{f.severity}</span>
                </td>
                <td className="px-4 py-2.5 text-xs font-mono text-muted-foreground">{f.cve ?? "—"}</td>
                <td className="px-4 py-2.5 text-xs font-medium tabular-nums">{f.cvss ?? "—"}</td>
                <td className="px-4 py-2.5">
                  <span className={cn("text-xs px-2 py-0.5 rounded-md font-medium", statusBadgeClass(f.status))}>{capitalize(f.status)}</span>
                </td>
                <td className="px-4 py-2.5 text-xs text-muted-foreground">{formatDate(f.createdAt)}</td>
                <td className="px-4 py-2.5">
                  <Link href={`/findings/${f.id}`}>
                    <Button variant="ghost" size="icon" className="h-7 w-7">
                      <ExternalLink className="w-3.5 h-3.5" />
                    </Button>
                  </Link>
                </td>
              </tr>
            ))}
            {!isLoading && list.length === 0 && (
              <tr><td colSpan={8} className="px-4 py-8 text-center text-sm text-muted-foreground">No findings match the current filters.</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
