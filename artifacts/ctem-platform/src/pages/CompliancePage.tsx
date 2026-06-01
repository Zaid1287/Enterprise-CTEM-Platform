import { useState } from "react";
import { Link } from "wouter";
import {
  useGetComplianceSummary, useListComplianceControls, useUpdateComplianceControl,
  getGetComplianceSummaryQueryKey, getListComplianceControlsQueryKey,
} from "@workspace/api-client-react";
import { useQueryClient } from "@tanstack/react-query";
import { ChevronRight } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { cn, statusBadgeClass, capitalize } from "@/lib/utils";

const FRAMEWORK_COLORS: Record<string, string> = {
  ISO27001: "border-blue-500/40 bg-blue-500/5",
  SOC2: "border-purple-500/40 bg-purple-500/5",
  "PCI-DSS": "border-orange-500/40 bg-orange-500/5",
  HIPAA: "border-green-500/40 bg-green-500/5",
  CIS: "border-yellow-500/40 bg-yellow-500/5",
};

export default function CompliancePage() {
  const [selectedFramework, setSelectedFramework] = useState<number | null>(null);
  const [statusFilter, setStatusFilter] = useState("");
  const queryClient = useQueryClient();

  const { data: summary, isLoading: loadingSummary } = useGetComplianceSummary({
    query: { queryKey: getGetComplianceSummaryQueryKey() },
  });

  const controlParams = {
    frameworkId: selectedFramework ?? undefined,
    status: statusFilter || undefined,
  };
  const { data: controls, isLoading: loadingControls } = useListComplianceControls(controlParams as any, {
    query: { queryKey: getListComplianceControlsQueryKey(controlParams as any) },
  });
  const updateControl = useUpdateComplianceControl();

  const handleStatusChange = async (controlId: number, status: string) => {
    await updateControl.mutateAsync({ controlId, data: { status } });
    queryClient.invalidateQueries({ queryKey: getListComplianceControlsQueryKey() });
    queryClient.invalidateQueries({ queryKey: getGetComplianceSummaryQueryKey() });
  };

  const frameworks = summary as any[] ?? [];

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-lg font-semibold">Compliance Management</h1>
        <p className="text-sm text-muted-foreground">Track compliance across security frameworks</p>
      </div>

      {/* Framework Cards */}
      {loadingSummary ? (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          {[...Array(5)].map((_, i) => <Skeleton key={i} className="h-32 rounded-xl" />)}
        </div>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          {frameworks.map((fw: any) => (
            <button
              key={fw.frameworkId}
              onClick={() => setSelectedFramework(selectedFramework === fw.frameworkId ? null : fw.frameworkId)}
              className={cn(
                "text-left bg-card rounded-xl p-4 border transition-all",
                FRAMEWORK_COLORS[fw.shortName] ?? "border-border",
                selectedFramework === fw.frameworkId ? "ring-1 ring-primary" : "hover:border-border"
              )}
            >
              <div className="flex items-start justify-between mb-3">
                <div>
                  <p className="text-sm font-semibold">{fw.shortName}</p>
                  <p className="text-xs text-muted-foreground">{fw.frameworkName}</p>
                </div>
                <div className="text-right">
                  <p className="text-2xl font-bold tabular-nums">{fw.score}%</p>
                  <p className="text-[10px] text-muted-foreground">compliance</p>
                </div>
              </div>
              <Progress value={fw.score} className="h-1.5 mb-2" />
              <div className="flex gap-3 text-xs">
                <span className="text-green-400">{fw.compliant} compliant</span>
                <span className="text-yellow-400">{fw.inProgress} in progress</span>
                <span className="text-red-400">{fw.nonCompliant} gaps</span>
              </div>
            </button>
          ))}
        </div>
      )}

      {/* Controls Table */}
      <div>
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-sm font-medium">
            {selectedFramework
              ? `Controls — ${frameworks.find((f: any) => f.frameworkId === selectedFramework)?.frameworkName ?? ""}`
              : "All Controls"}
          </h2>
          <div className="flex gap-2">
            <Select value={statusFilter} onValueChange={setStatusFilter}>
              <SelectTrigger className="w-36 h-7 text-xs">
                <SelectValue placeholder="All statuses" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="">All</SelectItem>
                <SelectItem value="compliant">Compliant</SelectItem>
                <SelectItem value="in_progress">In Progress</SelectItem>
                <SelectItem value="non_compliant">Non-Compliant</SelectItem>
                <SelectItem value="not_applicable">N/A</SelectItem>
              </SelectContent>
            </Select>
            {selectedFramework && (
              <Button variant="outline" size="sm" className="h-7 text-xs" onClick={() => setSelectedFramework(null)}>Clear</Button>
            )}
          </div>
        </div>

        <div className="bg-card border border-border rounded-xl overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Control ID</th>
                <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Title</th>
                <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Framework</th>
                <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Assigned To</th>
                <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Status</th>
              </tr>
            </thead>
            <tbody>
              {loadingControls && [...Array(5)].map((_, i) => (
                <tr key={i} className="border-b border-border/50">
                  {[...Array(5)].map((_, j) => <td key={j} className="px-4 py-3"><Skeleton className="h-4" /></td>)}
                </tr>
              ))}
              {!loadingControls && (controls as any[] ?? []).map((c: any) => (
                <tr key={c.id} className="border-b border-border/50 hover:bg-accent/30 transition-colors">
                  <td className="px-4 py-2.5 text-xs font-mono font-medium text-primary">{c.controlId}</td>
                  <td className="px-4 py-2.5 text-xs max-w-xs">
                    <p className="font-medium">{c.title}</p>
                    {c.evidence && <p className="text-muted-foreground line-clamp-1 mt-0.5">{c.evidence}</p>}
                  </td>
                  <td className="px-4 py-2.5 text-xs text-muted-foreground">{c.frameworkName}</td>
                  <td className="px-4 py-2.5 text-xs text-muted-foreground">{c.assignedTo ?? "—"}</td>
                  <td className="px-4 py-2.5">
                    <Select value={c.status} onValueChange={(v) => handleStatusChange(c.id, v)}>
                      <SelectTrigger className={cn("h-6 text-xs border-0 px-2 py-0 w-32", statusBadgeClass(c.status))}>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="compliant">Compliant</SelectItem>
                        <SelectItem value="in_progress">In Progress</SelectItem>
                        <SelectItem value="non_compliant">Non-Compliant</SelectItem>
                        <SelectItem value="not_applicable">N/A</SelectItem>
                      </SelectContent>
                    </Select>
                  </td>
                </tr>
              ))}
              {!loadingControls && (controls as any[] ?? []).length === 0 && (
                <tr><td colSpan={5} className="px-4 py-8 text-center text-sm text-muted-foreground">No controls found.</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
