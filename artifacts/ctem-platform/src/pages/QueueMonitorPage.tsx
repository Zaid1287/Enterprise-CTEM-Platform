import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Activity, CheckCircle2, XCircle, Clock, RefreshCw, Layers,
  Wifi, WifiOff, AlertTriangle, RotateCcw, Zap, Server,
  BarChart3, TrendingUp, Play, Pause, Database, Hash,
} from "lucide-react";
import { getToken } from "@/lib/auth";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";
import { useToast } from "@/hooks/use-toast";

interface ActiveScan {
  id: number;
  name: string;
  type: string;
  status: "running" | "pending";
  startedAt: string | null;
  assetCount: number;
}

interface RecentScan {
  id: number;
  name: string;
  type: string;
  status: string;
  startedAt: string | null;
  completedAt: string | null;
  assetCount: number;
}

interface DbStats {
  running: number;
  pending: number;
  completed: number;
  failed: number;
  cancelled: number;
}

interface QueueStat {
  name: string;
  active: number;
  waiting: number;
  completed: number;
  failed: number;
  delayed: number;
  paused: boolean;
}

interface QueueStatus {
  redis: { connected: boolean; url: string };
  queues: { scans: QueueStat; alerts: QueueStat };
  mode: "redis" | "in-memory";
  dbStats: DbStats;
  activeScans: ActiveScan[];
  recentScans: RecentScan[];
}

interface Job {
  id: string;
  name: string;
  data: Record<string, unknown>;
  progress: number;
  attemptsMade: number;
  failedReason?: string;
  timestamp: number;
  processedOn?: number;
  finishedOn?: number;
}

const base = () => import.meta.env.BASE_URL.replace(/\/$/, "");
const headers = () => ({ Authorization: `Bearer ${getToken()}`, "Content-Type": "application/json" });

async function fetchStatus(): Promise<QueueStatus> {
  const res = await fetch(`${base()}/api/queues/status`, { headers: headers() });
  if (!res.ok) throw new Error("Failed to fetch queue status");
  return res.json();
}

async function fetchJobs(queue: string, type: string): Promise<{ jobs: Job[]; redis: boolean }> {
  const res = await fetch(`${base()}/api/queues/jobs?queue=${queue}&type=${type}`, { headers: headers() });
  if (!res.ok) throw new Error("Failed to fetch jobs");
  return res.json();
}

async function retryFailed(queue: string): Promise<{ retried: number }> {
  const res = await fetch(`${base()}/api/queues/retry-failed`, {
    method: "POST", headers: headers(), body: JSON.stringify({ queue }),
  });
  if (!res.ok) throw new Error("Failed to retry jobs");
  return res.json();
}

function elapsed(startedAt: string | null): string {
  if (!startedAt) return "—";
  const ms = Date.now() - new Date(startedAt).getTime();
  const s = Math.floor(ms / 1000);
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m ${s % 60}s`;
  return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`;
}

function duration(start: string | null, end: string | null): string {
  if (!start || !end) return "—";
  const ms = new Date(end).getTime() - new Date(start).getTime();
  const s = Math.floor(ms / 1000);
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m ${s % 60}s`;
  return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`;
}

function StatCard({ label, value, icon: Icon, color, pulse }: {
  label: string; value: number; icon: React.ElementType; color: string; pulse?: boolean;
}) {
  return (
    <div className="bg-card border border-border rounded-xl p-4 flex items-center gap-3">
      <div className={cn("w-10 h-10 rounded-xl flex items-center justify-center shrink-0", color)}>
        <Icon className="w-5 h-5" />
      </div>
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-1.5">
          <p className="text-2xl font-bold tabular-nums leading-none">{value}</p>
          {pulse && value > 0 && (
            <span className="w-2 h-2 rounded-full bg-blue-400 animate-pulse inline-block" />
          )}
        </div>
        <p className="text-xs text-muted-foreground mt-0.5">{label}</p>
      </div>
    </div>
  );
}

function typeBadge(type: string) {
  const map: Record<string, string> = {
    pipeline: "border-cyan-500/30 text-cyan-400",
    scheduled: "border-purple-500/30 text-purple-400",
    manual: "border-muted text-muted-foreground",
    full: "border-blue-500/30 text-blue-400",
  };
  return map[type] ?? "border-muted text-muted-foreground";
}

export default function QueueMonitorPage() {
  const [selectedQueue, setSelectedQueue] = useState("scans");
  const [jobType, setJobType] = useState<"active" | "waiting" | "completed" | "failed" | "delayed">("active");
  const qc = useQueryClient();
  const { toast } = useToast();

  const { data: status, isLoading, error } = useQuery({
    queryKey: ["queue-status"],
    queryFn: fetchStatus,
    refetchInterval: 5000,
  });

  const { data: jobsData, isLoading: jobsLoading } = useQuery({
    queryKey: ["queue-jobs", selectedQueue, jobType],
    queryFn: () => fetchJobs(selectedQueue, jobType),
    refetchInterval: 5000,
    enabled: !!status?.redis.connected,
  });

  const retryMutation = useMutation({
    mutationFn: () => retryFailed(selectedQueue),
    onSuccess: (data) => {
      toast({ title: `Retried ${data.retried} failed job(s)` });
      qc.invalidateQueries({ queryKey: ["queue-status"] });
      qc.invalidateQueries({ queryKey: ["queue-jobs"] });
    },
    onError: () => toast({ title: "Retry failed", variant: "destructive" }),
  });

  const JOB_TYPES = ["active", "waiting", "completed", "failed", "delayed"] as const;
  const db = status?.dbStats;
  const totalFinished = (db?.completed ?? 0) + (db?.failed ?? 0) + (db?.cancelled ?? 0);
  const successRate = totalFinished > 0 ? Math.round(((db?.completed ?? 0) / totalFinished) * 100) : null;
  const totalActive = (db?.running ?? 0) + (db?.pending ?? 0);

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold">Queue Monitor</h1>
          <p className="text-sm text-muted-foreground mt-0.5">
            Real-time background job tracking — scan workers and alert dispatchers
          </p>
        </div>
        <Button
          variant="outline" size="sm"
          onClick={() => qc.invalidateQueries({ queryKey: ["queue-status"] })}
        >
          <RefreshCw className="w-3.5 h-3.5 mr-1.5" /> Refresh
        </Button>
      </div>

      {isLoading && (
        <div className="grid grid-cols-2 gap-4">
          <div className="grid grid-cols-3 gap-3 col-span-2">
            {[...Array(5)].map((_, i) => <Skeleton key={i} className="h-20 rounded-xl" />)}
          </div>
          <Skeleton className="h-60 rounded-xl col-span-1" />
          <Skeleton className="h-60 rounded-xl col-span-1" />
        </div>
      )}

      {error && (
        <div className="border border-red-500/30 bg-red-500/5 rounded-xl p-8 text-center space-y-2">
          <XCircle className="w-10 h-10 text-red-400 mx-auto" />
          <p className="font-semibold text-base">Failed to load queue status</p>
          <p className="text-sm text-muted-foreground">Check that the API server is running and you have admin access</p>
        </div>
      )}

      {status && (
        <>
          {/* Mode + success rate banner */}
          <div className={cn(
            "flex items-center gap-4 rounded-xl border px-5 py-3.5",
            status.redis.connected
              ? "border-green-500/25 bg-green-500/5"
              : "border-blue-500/25 bg-blue-500/5",
          )}>
            {status.redis.connected
              ? <Wifi className="w-5 h-5 text-green-400 shrink-0" />
              : <Database className="w-5 h-5 text-blue-400 shrink-0" />}
            <div className="flex-1 min-w-0">
              <p className="font-medium text-sm">
                {status.redis.connected
                  ? "Redis connected — BullMQ distributed workers active"
                  : "In-memory mode — jobs run in-process, tracked via database"}
              </p>
              <p className="text-xs text-muted-foreground mt-0.5">
                Mode: <code className="font-mono">{status.mode}</code>
                {" · "}Redis: <code className="font-mono">{status.redis.url}</code>
                {!status.redis.connected && " · Set REDIS_URL to enable distributed queuing"}
              </p>
            </div>
            <div className="flex items-center gap-6 shrink-0">
              {successRate !== null && (
                <div className="text-center">
                  <p className="text-xl font-bold text-green-400 tabular-nums">{successRate}%</p>
                  <p className="text-[10px] text-muted-foreground">success rate</p>
                </div>
              )}
              <div className="text-center">
                <p className={cn("text-xl font-bold tabular-nums", totalActive > 0 ? "text-blue-400" : "text-muted-foreground")}>
                  {totalActive}
                </p>
                <p className="text-[10px] text-muted-foreground">active / pending</p>
              </div>
            </div>
          </div>

          {/* Stat cards */}
          <div>
            <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-3 flex items-center gap-1.5">
              <BarChart3 className="w-3.5 h-3.5" /> Scan Statistics (Live from Database)
            </p>
            <div className="grid grid-cols-5 gap-3">
              <StatCard label="Running"   value={db?.running   ?? 0} icon={Activity}     color="bg-blue-500/15 text-blue-400"   pulse />
              <StatCard label="Pending"   value={db?.pending   ?? 0} icon={Clock}         color="bg-yellow-500/15 text-yellow-400" />
              <StatCard label="Completed" value={db?.completed ?? 0} icon={CheckCircle2}  color="bg-green-500/15 text-green-400"   />
              <StatCard label="Failed"    value={db?.failed    ?? 0} icon={XCircle}       color="bg-red-500/15 text-red-400"       />
              <StatCard label="Cancelled" value={db?.cancelled ?? 0} icon={Pause}         color="bg-muted text-muted-foreground"    />
            </div>
          </div>

          {/* Active + Recent scans — full width 2-col */}
          <div className="grid grid-cols-2 gap-4">
            {/* Active / pending */}
            <div className="bg-card border border-border rounded-xl overflow-hidden flex flex-col">
              <div className="px-4 py-3 border-b border-border flex items-center justify-between shrink-0">
                <div className="flex items-center gap-2">
                  <div className="w-2 h-2 rounded-full bg-blue-400 animate-pulse" />
                  <h3 className="text-sm font-semibold">Active & Pending Scans</h3>
                  {(status.activeScans?.length ?? 0) > 0 && (
                    <Badge variant="outline" className="text-[10px] border-blue-500/30 text-blue-400">
                      {status.activeScans.length}
                    </Badge>
                  )}
                </div>
                <Play className="w-3.5 h-3.5 text-muted-foreground" />
              </div>
              <div className="flex-1 overflow-auto max-h-72">
                {(status.activeScans?.length ?? 0) === 0 ? (
                  <div className="flex flex-col items-center justify-center py-10 text-muted-foreground gap-2">
                    <Server className="w-7 h-7 opacity-25" />
                    <p className="text-xs">No active scans right now</p>
                  </div>
                ) : (
                  status.activeScans.map(s => (
                    <div key={s.id} className="flex items-center gap-3 px-4 py-3 border-b border-border/40 last:border-0 hover:bg-accent/20 transition-colors">
                      <div className={cn(
                        "w-2 h-2 rounded-full shrink-0",
                        s.status === "running" ? "bg-blue-400 animate-pulse" : "bg-yellow-400",
                      )} />
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-medium truncate">{s.name}</p>
                        <div className="flex items-center gap-2 mt-0.5">
                          <Badge variant="outline" className={cn("text-[9px] capitalize px-1.5 py-0", typeBadge(s.type))}>
                            {s.type}
                          </Badge>
                          <span className="text-[10px] text-muted-foreground flex items-center gap-0.5">
                            <Hash className="w-2.5 h-2.5" />{s.assetCount} asset{s.assetCount !== 1 ? "s" : ""}
                          </span>
                        </div>
                      </div>
                      <div className="text-right shrink-0">
                        <Badge variant="outline" className={cn(
                          "text-[10px] capitalize",
                          s.status === "running" ? "border-blue-500/40 text-blue-400" : "border-yellow-500/40 text-yellow-400",
                        )}>
                          {s.status}
                        </Badge>
                        <p className="text-[10px] text-muted-foreground mt-0.5">{elapsed(s.startedAt)}</p>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>

            {/* Recent completed/failed */}
            <div className="bg-card border border-border rounded-xl overflow-hidden flex flex-col">
              <div className="px-4 py-3 border-b border-border flex items-center justify-between shrink-0">
                <div className="flex items-center gap-2">
                  <TrendingUp className="w-3.5 h-3.5 text-muted-foreground" />
                  <h3 className="text-sm font-semibold">Recent Scans</h3>
                </div>
                <Layers className="w-3.5 h-3.5 text-muted-foreground" />
              </div>
              <div className="flex-1 overflow-auto max-h-72">
                {(status.recentScans?.length ?? 0) === 0 ? (
                  <div className="flex flex-col items-center justify-center py-10 text-muted-foreground gap-2">
                    <BarChart3 className="w-7 h-7 opacity-25" />
                    <p className="text-xs">No completed scans yet</p>
                  </div>
                ) : (
                  status.recentScans.map(s => (
                    <div key={s.id} className="flex items-center gap-3 px-4 py-2.5 border-b border-border/40 last:border-0 hover:bg-accent/20 transition-colors">
                      {s.status === "completed"
                        ? <CheckCircle2 className="w-3.5 h-3.5 text-green-400 shrink-0" />
                        : s.status === "failed"
                          ? <XCircle className="w-3.5 h-3.5 text-red-400 shrink-0" />
                          : <Clock className="w-3.5 h-3.5 text-muted-foreground shrink-0" />}
                      <div className="flex-1 min-w-0">
                        <p className="text-sm truncate">{s.name}</p>
                        <div className="flex items-center gap-2 mt-0.5">
                          <Badge variant="outline" className={cn("text-[9px] capitalize px-1.5 py-0", typeBadge(s.type))}>
                            {s.type}
                          </Badge>
                          <span className="text-[10px] text-muted-foreground flex items-center gap-0.5">
                            <Hash className="w-2.5 h-2.5" />{s.assetCount}
                          </span>
                        </div>
                      </div>
                      <div className="text-right shrink-0">
                        <p className="text-xs text-muted-foreground">{duration(s.startedAt, s.completedAt)}</p>
                        <p className="text-[10px] text-muted-foreground/60">
                          {s.completedAt ? new Date(s.completedAt).toLocaleTimeString() : "—"}
                        </p>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>

          {/* BullMQ details — Redis only */}
          {status.redis.connected && (
            <div className="space-y-4">
              <div className="flex items-center gap-2">
                <div className="h-px flex-1 bg-border" />
                <p className="text-xs text-muted-foreground font-medium px-2">BullMQ Queue Details</p>
                <div className="h-px flex-1 bg-border" />
              </div>

              <div className="grid grid-cols-2 gap-4">
                {(["scans", "alerts"] as const).map(qn => {
                  const stat = status.queues[qn];
                  const isSel = selectedQueue === qn;
                  return (
                    <button
                      key={qn}
                      className={cn(
                        "text-left border rounded-xl p-4 transition-all",
                        isSel ? "border-primary/50 bg-primary/5" : "border-border bg-card hover:border-border/70",
                      )}
                      onClick={() => setSelectedQueue(qn)}
                    >
                      <div className="flex items-center justify-between mb-3">
                        <div>
                          <p className="font-semibold text-sm font-mono">{stat.name}</p>
                          {stat.paused && <Badge variant="secondary" className="mt-1 text-[10px]">PAUSED</Badge>}
                        </div>
                        <Zap className={cn("w-4 h-4", isSel ? "text-primary" : "text-muted-foreground")} />
                      </div>
                      <div className="grid grid-cols-5 gap-1.5 text-xs">
                        {[
                          { label: "Active",    val: stat.active,    color: "text-blue-400" },
                          { label: "Waiting",   val: stat.waiting,   color: "text-yellow-400" },
                          { label: "Done",      val: stat.completed, color: "text-green-400" },
                          { label: "Failed",    val: stat.failed,    color: "text-red-400" },
                          { label: "Delayed",   val: stat.delayed,   color: "text-purple-400" },
                        ].map(({ label, val, color }) => (
                          <div key={label} className="bg-muted/40 rounded-lg px-2 py-1.5 text-center">
                            <p className={cn("font-bold tabular-nums", color)}>{val}</p>
                            <p className="text-[9px] text-muted-foreground">{label}</p>
                          </div>
                        ))}
                      </div>
                    </button>
                  );
                })}
              </div>

              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex gap-1 bg-muted/50 rounded-lg p-1">
                    {JOB_TYPES.map(t => (
                      <button
                        key={t}
                        onClick={() => setJobType(t)}
                        className={cn(
                          "px-3 py-1.5 text-xs font-medium rounded-md capitalize transition-colors",
                          jobType === t ? "bg-background text-foreground shadow-sm" : "text-muted-foreground hover:text-foreground",
                        )}
                      >
                        {t}
                        {t === "failed" && status.queues[selectedQueue as "scans" | "alerts"]?.failed > 0 && (
                          <span className="ml-1 text-red-400">({status.queues[selectedQueue as "scans" | "alerts"].failed})</span>
                        )}
                      </button>
                    ))}
                  </div>
                  {jobType === "failed" && (
                    <Button size="sm" variant="outline" onClick={() => retryMutation.mutate()} disabled={retryMutation.isPending}>
                      <RotateCcw className="w-3.5 h-3.5 mr-1.5" /> Retry All Failed
                    </Button>
                  )}
                </div>

                {jobsLoading && (
                  <div className="space-y-2">
                    {[...Array(3)].map((_, i) => <Skeleton key={i} className="h-16 rounded-xl" />)}
                  </div>
                )}
                {!jobsLoading && jobsData?.jobs.length === 0 && (
                  <div className="text-center py-10 text-muted-foreground border border-border rounded-xl">
                    <Layers className="w-6 h-6 mx-auto mb-2 opacity-30" />
                    <p className="text-sm">No {jobType} jobs in <code className="font-mono">{selectedQueue}</code></p>
                  </div>
                )}
                {!jobsLoading && jobsData?.jobs.map(job => (
                  <div key={job.id} className="border border-border rounded-xl p-3.5 text-sm space-y-2">
                    <div className="flex items-start justify-between gap-2">
                      <div className="min-w-0">
                        <p className="font-medium truncate">{job.name}</p>
                        <p className="font-mono text-[10px] text-muted-foreground">#{job.id}</p>
                      </div>
                      <div className="flex items-center gap-1.5 shrink-0">
                        {job.attemptsMade > 1 && (
                          <Badge variant="outline" className="text-[10px]">{job.attemptsMade} attempts</Badge>
                        )}
                        <span className="text-xs text-muted-foreground">{new Date(job.timestamp).toLocaleTimeString()}</span>
                      </div>
                    </div>
                    {job.failedReason && (
                      <p className="text-xs text-red-400 bg-red-500/10 rounded-lg px-2.5 py-1.5 font-mono truncate">{job.failedReason}</p>
                    )}
                    {job.finishedOn && job.processedOn && (
                      <p className="text-xs text-muted-foreground">Duration: {((job.finishedOn - job.processedOn) / 1000).toFixed(1)}s</p>
                    )}
                    {typeof job.progress === "number" && job.progress > 0 && (
                      <div className="h-1.5 bg-muted rounded-full overflow-hidden">
                        <div className="h-full bg-gradient-to-r from-blue-500 to-cyan-500 rounded-full" style={{ width: `${job.progress}%` }} />
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* In-memory notice */}
          {!status.redis.connected && (
            <div className="border border-border rounded-xl p-5 bg-muted/20">
              <div className="flex items-start gap-3">
                <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                <div className="space-y-1 flex-1">
                  <p className="text-sm font-medium">BullMQ job list not available in in-memory mode</p>
                  <p className="text-xs text-muted-foreground leading-relaxed">
                    Individual job history requires Redis. Scan statistics above are pulled directly from the database and are always accurate.
                    To enable distributed job tracking with full history and retry logic, set{" "}
                    <code className="font-mono bg-muted px-1 rounded">REDIS_URL</code> in environment secrets.
                  </p>
                  <p className="text-xs font-mono bg-muted rounded-lg p-2.5 mt-2 text-muted-foreground">
                    REDIS_URL=redis://default:&lt;password&gt;@&lt;host&gt;:6379
                  </p>
                </div>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}
