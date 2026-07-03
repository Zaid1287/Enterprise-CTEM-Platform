import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Activity, CheckCircle2, XCircle, Clock, RefreshCw, Layers,
  Wifi, WifiOff, AlertTriangle, RotateCcw, Zap, Server,
  BarChart3, TrendingUp, Play, Pause, Database, Hash,
  Cpu, Radio, Calendar, Trash2, ChevronRight,
} from "lucide-react";
import { getToken } from "@/lib/auth";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";
import { useToast } from "@/hooks/use-toast";
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend,
} from "recharts";

/* ─── Types ─────────────────────────────────────────────────────────────── */
interface ActiveScan {
  id: number; name: string; type: string;
  status: "running" | "pending"; startedAt: string | null; assetCount: number;
}
interface RecentScan {
  id: number; name: string; type: string; status: string;
  startedAt: string | null; completedAt: string | null; assetCount: number;
}
interface DbStats { running: number; pending: number; completed: number; failed: number; cancelled: number; }
interface QueueStat { name: string; active: number; waiting: number; completed: number; failed: number; delayed: number; paused: boolean; }
interface InProcess { activeScans: number; pendingCount: number; maxConcurrent: number; pendingScanIds: number[]; }
interface WorkerInfo { running: boolean; mode: string; status: string; concurrency: number; }
interface WorkerHealth { scanWorker: WorkerInfo; alertWorker: WorkerInfo; redis: boolean; }
interface ThroughputHour { hour: string | null; completed: number; failed: number; cancelled: number; }
interface ScheduledScan { id: number; name: string; frequency: string; nextRunAt: string | null; lastRunAt: string | null; assetName: string | null; }
interface QueueStatus {
  redis: { connected: boolean; url: string };
  queues: { scans: QueueStat; alerts: QueueStat };
  mode: "redis" | "in-memory";
  inProcess: InProcess;
  depthWarning: boolean;
  dbStats: DbStats;
  activeScans: ActiveScan[];
  recentScans: RecentScan[];
  upcomingSchedules: ScheduledScan[];
}
interface Job {
  id: string; name: string; data: Record<string, unknown>;
  progress: number; attemptsMade: number; failedReason?: string;
  timestamp: number; processedOn?: number; finishedOn?: number;
}

/* ─── API helpers ────────────────────────────────────────────────────────── */
const base = () => import.meta.env.BASE_URL.replace(/\/$/, "");
const authHeaders = () => ({ Authorization: `Bearer ${getToken()}`, "Content-Type": "application/json" });

async function api<T>(path: string, opts?: RequestInit): Promise<T> {
  const res = await fetch(`${base()}${path}`, { headers: authHeaders(), ...opts });
  if (!res.ok) { const e = await res.json().catch(() => ({})); throw new Error((e as any).error ?? "Request failed"); }
  return res.json();
}

const fetchStatus     = () => api<QueueStatus>("/api/queues/status");
const fetchWorkerHealth = () => api<WorkerHealth>("/api/queues/worker-health");
const fetchThroughput = () => api<{ hourly: ThroughputHour[] }>("/api/queues/throughput");
const fetchJobs = (q: string, t: string) => api<{ jobs: Job[]; redis: boolean }>(`/api/queues/jobs?queue=${q}&type=${t}`);
const retryFailed = (q: string) => api<{ retried: number }>("/api/queues/retry-failed", { method: "POST", body: JSON.stringify({ queue: q }) });
const pauseQueue  = (q: string) => api<any>("/api/queues/pause",  { method: "POST", body: JSON.stringify({ queue: q }) });
const resumeQueue = (q: string) => api<any>("/api/queues/resume", { method: "POST", body: JSON.stringify({ queue: q }) });
const killJob     = (jobId: string, q: string) => api<any>(`/api/queues/jobs/${jobId}?queue=${q}`, { method: "DELETE" });

/* ─── Small helpers ──────────────────────────────────────────────────────── */
function elapsed(s: string | null) {
  if (!s) return "—";
  const ms = Date.now() - new Date(s).getTime();
  const sec = Math.floor(ms / 1000);
  if (sec < 60) return `${sec}s`;
  if (sec < 3600) return `${Math.floor(sec / 60)}m ${sec % 60}s`;
  return `${Math.floor(sec / 3600)}h ${Math.floor((sec % 3600) / 60)}m`;
}
function duration(a: string | null, b: string | null) {
  if (!a || !b) return "—";
  const s = Math.floor((new Date(b).getTime() - new Date(a).getTime()) / 1000);
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m ${s % 60}s`;
  return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`;
}
function typeBadge(t: string) {
  const m: Record<string, string> = {
    pipeline: "border-cyan-500/30 text-cyan-400", scheduled: "border-purple-500/30 text-purple-400",
    manual: "border-muted text-muted-foreground", full: "border-blue-500/30 text-blue-400",
  };
  return m[t] ?? "border-muted text-muted-foreground";
}
function fmtFreq(f: string) {
  return f.charAt(0).toUpperCase() + f.slice(1);
}
function fmtHour(iso: string | null) {
  if (!iso) return "?";
  const d = new Date(iso);
  return `${d.getHours().toString().padStart(2, "0")}:00`;
}

/* ─── Sub-components ─────────────────────────────────────────────────────── */
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
          {pulse && value > 0 && <span className="w-2 h-2 rounded-full bg-blue-400 animate-pulse inline-block" />}
        </div>
        <p className="text-xs text-muted-foreground mt-0.5">{label}</p>
      </div>
    </div>
  );
}

function WorkerCard({ name, info }: { name: string; info: WorkerInfo }) {
  const statusColor =
    info.status === "active"   ? "bg-green-500/15 text-green-400 border-green-500/30" :
    info.status === "idle"     ? "bg-yellow-500/15 text-yellow-400 border-yellow-500/30" :
    "bg-muted text-muted-foreground border-border";
  const dotColor =
    info.status === "active"   ? "bg-green-400 animate-pulse" :
    info.status === "idle"     ? "bg-yellow-400" :
    "bg-muted-foreground";
  return (
    <div className="bg-card border border-border rounded-xl p-4 space-y-3">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Cpu className="w-4 h-4 text-muted-foreground" />
          <span className="text-sm font-semibold">{name}</span>
        </div>
        <span className={cn("text-[10px] px-2 py-0.5 rounded-full border font-medium capitalize flex items-center gap-1", statusColor)}>
          <span className={cn("w-1.5 h-1.5 rounded-full inline-block", dotColor)} />
          {info.status}
        </span>
      </div>
      <div className="grid grid-cols-3 gap-2 text-xs">
        <div className="bg-muted/40 rounded-lg px-2.5 py-2 text-center">
          <p className="font-semibold capitalize">{info.mode}</p>
          <p className="text-[10px] text-muted-foreground">mode</p>
        </div>
        <div className="bg-muted/40 rounded-lg px-2.5 py-2 text-center">
          <p className={cn("font-semibold", info.running ? "text-green-400" : "text-muted-foreground")}>
            {info.running ? "Online" : "Offline"}
          </p>
          <p className="text-[10px] text-muted-foreground">state</p>
        </div>
        <div className="bg-muted/40 rounded-lg px-2.5 py-2 text-center">
          <p className="font-semibold">{info.concurrency > 0 ? info.concurrency : "—"}</p>
          <p className="text-[10px] text-muted-foreground">concurrency</p>
        </div>
      </div>
    </div>
  );
}

const TOOLTIP_STYLE = {
  background: "hsl(222 47% 11%)", border: "1px solid hsl(217 33% 17%)",
  borderRadius: "8px", fontSize: "11px",
};

/* ═══════════════════════════════════════════════════════════════════════════ */
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
  const { data: workerHealth } = useQuery({
    queryKey: ["worker-health"],
    queryFn: fetchWorkerHealth,
    refetchInterval: 10_000,
  });
  const { data: throughputData } = useQuery({
    queryKey: ["queue-throughput"],
    queryFn: fetchThroughput,
    refetchInterval: 60_000,
    staleTime: 30_000,
  });
  const { data: jobsData, isLoading: jobsLoading } = useQuery({
    queryKey: ["queue-jobs", selectedQueue, jobType],
    queryFn: () => fetchJobs(selectedQueue, jobType),
    refetchInterval: 5000,
    enabled: !!status?.redis.connected,
  });

  const retryMut = useMutation({
    mutationFn: () => retryFailed(selectedQueue),
    onSuccess: (d) => { toast({ title: `Retried ${d.retried} failed job(s)` }); invalidate(); },
    onError: (e: Error) => toast({ title: e.message, variant: "destructive" }),
  });
  const pauseMut = useMutation({
    mutationFn: () => pauseQueue(selectedQueue),
    onSuccess: () => { toast({ title: `Queue "${selectedQueue}" paused` }); invalidate(); },
    onError: (e: Error) => toast({ title: e.message, variant: "destructive" }),
  });
  const resumeMut = useMutation({
    mutationFn: () => resumeQueue(selectedQueue),
    onSuccess: () => { toast({ title: `Queue "${selectedQueue}" resumed` }); invalidate(); },
    onError: (e: Error) => toast({ title: e.message, variant: "destructive" }),
  });
  const killMut = useMutation({
    mutationFn: ({ jobId }: { jobId: string }) => killJob(jobId, selectedQueue),
    onSuccess: () => { toast({ title: "Job removed" }); invalidate(); },
    onError: (e: Error) => toast({ title: e.message, variant: "destructive" }),
  });

  function invalidate() {
    qc.invalidateQueries({ queryKey: ["queue-status"] });
    qc.invalidateQueries({ queryKey: ["queue-jobs"] });
  }

  const JOB_TYPES = ["active", "waiting", "completed", "failed", "delayed"] as const;
  const dbSt = status?.dbStats;
  const totalFinished = (dbSt?.completed ?? 0) + (dbSt?.failed ?? 0) + (dbSt?.cancelled ?? 0);
  const successRate = totalFinished > 0 ? Math.round(((dbSt?.completed ?? 0) / totalFinished) * 100) : null;
  const totalActive = (dbSt?.running ?? 0) + (dbSt?.pending ?? 0);
  const inP = status?.inProcess;
  const selQ = status?.queues[selectedQueue as "scans" | "alerts"];
  const isPaused = selQ?.paused ?? false;

  // Throughput chart data — fill missing hours
  const throughputHourly = (() => {
    const raw = throughputData?.hourly ?? [];
    if (raw.length === 0) return [];
    return raw.map(r => ({
      hour: fmtHour(r.hour),
      Completed: r.completed,
      Failed: r.failed,
      Cancelled: r.cancelled,
    }));
  })();

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold">Queue Monitor</h1>
          <p className="text-sm text-muted-foreground mt-0.5">
            Real-time background job tracking — scan workers, alert dispatchers, and scheduled jobs
          </p>
        </div>
        <Button variant="outline" size="sm" onClick={() => { invalidate(); qc.invalidateQueries({ queryKey: ["worker-health"] }); qc.invalidateQueries({ queryKey: ["queue-throughput"] }); }}>
          <RefreshCw className="w-3.5 h-3.5 mr-1.5" /> Refresh
        </Button>
      </div>

      {isLoading && (
        <div className="space-y-4">
          <Skeleton className="h-16 rounded-xl" />
          <div className="grid grid-cols-5 gap-3">{[...Array(5)].map((_, i) => <Skeleton key={i} className="h-20 rounded-xl" />)}</div>
          <div className="grid grid-cols-2 gap-4">{[...Array(2)].map((_, i) => <Skeleton key={i} className="h-40 rounded-xl" />)}</div>
        </div>
      )}
      {error && (
        <div className="border border-red-500/30 bg-red-500/5 rounded-xl p-8 text-center space-y-2">
          <XCircle className="w-10 h-10 text-red-400 mx-auto" />
          <p className="font-semibold">Failed to load queue status</p>
          <p className="text-sm text-muted-foreground">Check API server is running and you have admin access</p>
        </div>
      )}

      {status && (
        <>
          {/* ── Queue depth warning ─────────────────────────────────────────── */}
          {status.depthWarning && (
            <div className="flex items-center gap-3 border border-amber-500/30 bg-amber-500/5 rounded-xl px-5 py-3.5">
              <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0" />
              <div className="flex-1">
                <p className="text-sm font-medium text-amber-300">Queue depth alert — scan backlog growing</p>
                <p className="text-xs text-muted-foreground mt-0.5">
                  {inP?.activeScans} active + {inP?.pendingCount} pending exceeds {(inP?.maxConcurrent ?? 5) * 2} (2× max concurrent).
                  Consider increasing <code className="font-mono">MAX_CONCURRENT_SCANS</code> or pausing new scans.
                </p>
              </div>
            </div>
          )}

          {/* ── Mode + success rate banner ──────────────────────────────────── */}
          <div className={cn(
            "flex items-center gap-4 rounded-xl border px-5 py-3.5",
            status.redis.connected ? "border-green-500/25 bg-green-500/5" : "border-blue-500/25 bg-blue-500/5",
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

          {/* ── DB stat cards ────────────────────────────────────────────────── */}
          <div>
            <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-3 flex items-center gap-1.5">
              <BarChart3 className="w-3.5 h-3.5" /> Scan Statistics (Live from Database)
            </p>
            <div className="grid grid-cols-5 gap-3">
              <StatCard label="Running"   value={dbSt?.running   ?? 0} icon={Activity}    color="bg-blue-500/15 text-blue-400"    pulse />
              <StatCard label="Pending"   value={dbSt?.pending   ?? 0} icon={Clock}        color="bg-yellow-500/15 text-yellow-400" />
              <StatCard label="Completed" value={dbSt?.completed ?? 0} icon={CheckCircle2} color="bg-green-500/15 text-green-400"   />
              <StatCard label="Failed"    value={dbSt?.failed    ?? 0} icon={XCircle}      color="bg-red-500/15 text-red-400"       />
              <StatCard label="Cancelled" value={dbSt?.cancelled ?? 0} icon={Pause}        color="bg-muted text-muted-foreground"   />
            </div>
          </div>

          {/* ── In-process FIFO queue (both modes) ─────────────────────────── */}
          {inP && (
            <div className="bg-card border border-border rounded-xl p-4 space-y-3">
              <div className="flex items-center justify-between">
                <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground flex items-center gap-1.5">
                  <Server className="w-3.5 h-3.5" /> In-Process Queue (Node.js FIFO)
                </p>
                <span className="text-[10px] text-muted-foreground font-mono">
                  max concurrency: {inP.maxConcurrent}
                </span>
              </div>
              <div className="grid grid-cols-3 gap-3">
                <div className={cn("rounded-xl px-4 py-3 border text-center", inP.activeScans > 0 ? "bg-blue-500/10 border-blue-500/30" : "bg-muted/30 border-border")}>
                  <p className={cn("text-2xl font-bold tabular-nums", inP.activeScans > 0 ? "text-blue-400" : "text-muted-foreground")}>
                    {inP.activeScans}
                    {inP.activeScans > 0 && <span className="inline-block w-2 h-2 rounded-full bg-blue-400 animate-pulse ml-1.5 align-middle" />}
                  </p>
                  <p className="text-[10px] text-muted-foreground mt-0.5">running now</p>
                </div>
                <div className={cn("rounded-xl px-4 py-3 border text-center", inP.pendingCount > 0 ? "bg-yellow-500/10 border-yellow-500/30" : "bg-muted/30 border-border")}>
                  <p className={cn("text-2xl font-bold tabular-nums", inP.pendingCount > 0 ? "text-yellow-400" : "text-muted-foreground")}>
                    {inP.pendingCount}
                  </p>
                  <p className="text-[10px] text-muted-foreground mt-0.5">in queue</p>
                </div>
                <div className="rounded-xl px-4 py-3 border bg-muted/30 border-border text-center">
                  <p className="text-2xl font-bold tabular-nums text-muted-foreground">{inP.maxConcurrent}</p>
                  <p className="text-[10px] text-muted-foreground mt-0.5">max concurrent</p>
                </div>
              </div>
              {inP.pendingScanIds.length > 0 && (
                <div className="flex flex-wrap gap-1.5">
                  <span className="text-[10px] text-muted-foreground font-medium">Queued scan IDs:</span>
                  {inP.pendingScanIds.map(id => (
                    <span key={id} className="font-mono text-[10px] bg-muted/60 border border-border/50 rounded px-1.5 py-0.5 text-muted-foreground">
                      #{id}
                    </span>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* ── Worker health ────────────────────────────────────────────────── */}
          {workerHealth && (
            <div>
              <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-3 flex items-center gap-1.5">
                <Radio className="w-3.5 h-3.5" /> Worker Health
              </p>
              <div className="grid grid-cols-2 gap-3">
                <WorkerCard name="Scan Worker" info={workerHealth.scanWorker} />
                <WorkerCard name="Alert Worker" info={workerHealth.alertWorker} />
              </div>
            </div>
          )}

          {/* ── 24h Throughput chart ─────────────────────────────────────────── */}
          <div className="bg-card border border-border rounded-xl p-4">
            <div className="flex items-center justify-between mb-4">
              <p className="text-sm font-semibold flex items-center gap-2">
                <TrendingUp className="w-4 h-4 text-muted-foreground" />
                Scan Throughput — Last 24 Hours
              </p>
              {throughputHourly.length === 0 && (
                <span className="text-xs text-muted-foreground">No data yet</span>
              )}
            </div>
            {throughputHourly.length > 0 ? (
              <ResponsiveContainer width="100%" height={180}>
                <BarChart data={throughputHourly} barSize={12}>
                  <CartesianGrid strokeDasharray="3 3" stroke="hsl(217 33% 17%)" />
                  <XAxis dataKey="hour" tick={{ fill: "#64748b", fontSize: 10 }} />
                  <YAxis tick={{ fill: "#64748b", fontSize: 10 }} allowDecimals={false} />
                  <Tooltip contentStyle={TOOLTIP_STYLE} />
                  <Legend wrapperStyle={{ fontSize: 11 }} />
                  <Bar dataKey="Completed" fill="#22c55e" radius={[3,3,0,0]} />
                  <Bar dataKey="Failed"    fill="#ef4444" radius={[3,3,0,0]} />
                  <Bar dataKey="Cancelled" fill="#64748b" radius={[3,3,0,0]} />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex flex-col items-center justify-center h-36 text-muted-foreground gap-2">
                <BarChart3 className="w-8 h-8 opacity-25" />
                <p className="text-xs">No completed scans in the last 24 hours</p>
              </div>
            )}
          </div>

          {/* ── Active & Recent scans ─────────────────────────────────────────── */}
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
                      <div className={cn("w-2 h-2 rounded-full shrink-0", s.status === "running" ? "bg-blue-400 animate-pulse" : "bg-yellow-400")} />
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-medium truncate">{s.name}</p>
                        <div className="flex items-center gap-2 mt-0.5">
                          <Badge variant="outline" className={cn("text-[9px] capitalize px-1.5 py-0", typeBadge(s.type))}>{s.type}</Badge>
                          <span className="text-[10px] text-muted-foreground flex items-center gap-0.5">
                            <Hash className="w-2.5 h-2.5" />{s.assetCount} asset{s.assetCount !== 1 ? "s" : ""}
                          </span>
                        </div>
                      </div>
                      <div className="text-right shrink-0">
                        <Badge variant="outline" className={cn("text-[10px] capitalize", s.status === "running" ? "border-blue-500/40 text-blue-400" : "border-yellow-500/40 text-yellow-400")}>
                          {s.status}
                        </Badge>
                        <p className="text-[10px] text-muted-foreground mt-0.5">{elapsed(s.startedAt)}</p>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>

            {/* Recent scans */}
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
                    <div key={s.id} className="flex items-center gap-3 px-4 py-2.5 border-b border-border/40 last:border-0 hover:bg-accent/20">
                      {s.status === "completed"
                        ? <CheckCircle2 className="w-3.5 h-3.5 text-green-400 shrink-0" />
                        : s.status === "failed"
                          ? <XCircle className="w-3.5 h-3.5 text-red-400 shrink-0" />
                          : <Clock className="w-3.5 h-3.5 text-muted-foreground shrink-0" />}
                      <div className="flex-1 min-w-0">
                        <p className="text-sm truncate">{s.name}</p>
                        <div className="flex items-center gap-2 mt-0.5">
                          <Badge variant="outline" className={cn("text-[9px] capitalize px-1.5 py-0", typeBadge(s.type))}>{s.type}</Badge>
                          <span className="text-[10px] text-muted-foreground flex items-center gap-0.5"><Hash className="w-2.5 h-2.5" />{s.assetCount}</span>
                        </div>
                      </div>
                      <div className="text-right shrink-0">
                        <p className="text-xs text-muted-foreground">{duration(s.startedAt, s.completedAt)}</p>
                        <p className="text-[10px] text-muted-foreground/60">{s.completedAt ? new Date(s.completedAt).toLocaleTimeString() : "—"}</p>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>

          {/* ── Upcoming scheduled scans ─────────────────────────────────────── */}
          {(status.upcomingSchedules?.length ?? 0) > 0 && (
            <div className="bg-card border border-border rounded-xl overflow-hidden">
              <div className="px-4 py-3 border-b border-border flex items-center gap-2">
                <Calendar className="w-3.5 h-3.5 text-muted-foreground" />
                <h3 className="text-sm font-semibold">Upcoming Scheduled Scans</h3>
                <Badge variant="outline" className="text-[10px] ml-auto">{status.upcomingSchedules.length}</Badge>
              </div>
              <div className="divide-y divide-border/40">
                {status.upcomingSchedules.map(s => (
                  <div key={s.id} className="flex items-center gap-3 px-4 py-2.5 hover:bg-accent/20 transition-colors">
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium truncate">{s.name || `Schedule #${s.id}`}</p>
                      <p className="text-[10px] text-muted-foreground truncate">{s.assetName ?? "All assets"}</p>
                    </div>
                    <Badge variant="outline" className="text-[10px] border-purple-500/30 text-purple-400 shrink-0">{fmtFreq(s.frequency)}</Badge>
                    <div className="text-right shrink-0">
                      <p className="text-xs font-medium">{s.nextRunAt ? elapsed(s.nextRunAt) + " ago" : "—"}</p>
                      <p className="text-[10px] text-muted-foreground">{s.nextRunAt ? new Date(s.nextRunAt).toLocaleString() : "—"}</p>
                    </div>
                    <ChevronRight className="w-3.5 h-3.5 text-muted-foreground shrink-0" />
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* ── BullMQ details (Redis mode only) ─────────────────────────────── */}
          {status.redis.connected && (
            <div className="space-y-4">
              <div className="flex items-center gap-2">
                <div className="h-px flex-1 bg-border" />
                <p className="text-xs text-muted-foreground font-medium px-2">BullMQ Queue Details</p>
                <div className="h-px flex-1 bg-border" />
              </div>

              {/* Queue selector cards + pause/resume */}
              <div className="grid grid-cols-2 gap-4">
                {(["scans", "alerts"] as const).map(qn => {
                  const stat = status.queues[qn];
                  const isSel = selectedQueue === qn;
                  return (
                    <button
                      key={qn}
                      className={cn("text-left border rounded-xl p-4 transition-all", isSel ? "border-primary/50 bg-primary/5" : "border-border bg-card hover:border-border/70")}
                      onClick={() => setSelectedQueue(qn)}
                    >
                      <div className="flex items-center justify-between mb-3">
                        <div>
                          <p className="font-semibold text-sm font-mono">{stat.name}</p>
                          {stat.paused && <Badge variant="secondary" className="mt-1 text-[10px]">PAUSED</Badge>}
                        </div>
                        <div className="flex items-center gap-2">
                          {isSel && (
                            stat.paused ? (
                              <Button size="sm" variant="outline" className="h-6 text-[10px] px-2 border-green-500/40 text-green-400 hover:bg-green-500/10"
                                onClick={e => { e.stopPropagation(); resumeMut.mutate(); }} disabled={resumeMut.isPending}>
                                <Play className="w-2.5 h-2.5 mr-1" /> Resume
                              </Button>
                            ) : (
                              <Button size="sm" variant="outline" className="h-6 text-[10px] px-2 border-yellow-500/40 text-yellow-400 hover:bg-yellow-500/10"
                                onClick={e => { e.stopPropagation(); pauseMut.mutate(); }} disabled={pauseMut.isPending}>
                                <Pause className="w-2.5 h-2.5 mr-1" /> Pause
                              </Button>
                            )
                          )}
                          <Zap className={cn("w-4 h-4", isSel ? "text-primary" : "text-muted-foreground")} />
                        </div>
                      </div>
                      <div className="grid grid-cols-5 gap-1.5 text-xs">
                        {[
                          { label: "Active",  val: stat.active,    color: "text-blue-400" },
                          { label: "Waiting", val: stat.waiting,   color: "text-yellow-400" },
                          { label: "Done",    val: stat.completed, color: "text-green-400" },
                          { label: "Failed",  val: stat.failed,    color: "text-red-400" },
                          { label: "Delayed", val: stat.delayed,   color: "text-purple-400" },
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

              {/* Job type tabs + actions */}
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex gap-1 bg-muted/50 rounded-lg p-1">
                    {JOB_TYPES.map(t => (
                      <button key={t} onClick={() => setJobType(t)}
                        className={cn("px-3 py-1.5 text-xs font-medium rounded-md capitalize transition-colors",
                          jobType === t ? "bg-background text-foreground shadow-sm" : "text-muted-foreground hover:text-foreground")}>
                        {t}
                        {t === "failed" && selQ && selQ.failed > 0 && (
                          <span className="ml-1 text-red-400">({selQ.failed})</span>
                        )}
                      </button>
                    ))}
                  </div>
                  <div className="flex items-center gap-2">
                    {jobType === "failed" && (
                      <Button size="sm" variant="outline" onClick={() => retryMut.mutate()} disabled={retryMut.isPending}>
                        <RotateCcw className="w-3.5 h-3.5 mr-1.5" /> Retry All Failed
                      </Button>
                    )}
                  </div>
                </div>

                {jobsLoading && <div className="space-y-2">{[...Array(3)].map((_, i) => <Skeleton key={i} className="h-16 rounded-xl" />)}</div>}

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
                        {job.attemptsMade > 1 && <Badge variant="outline" className="text-[10px]">{job.attemptsMade} attempts</Badge>}
                        <span className="text-xs text-muted-foreground">{new Date(job.timestamp).toLocaleTimeString()}</span>
                        {(jobType === "active" || jobType === "waiting") && (
                          <Button size="sm" variant="ghost" className="h-6 w-6 p-0 text-red-400 hover:text-red-300 hover:bg-red-500/10"
                            onClick={() => killMut.mutate({ jobId: job.id })} disabled={killMut.isPending}>
                            <Trash2 className="w-3 h-3" />
                          </Button>
                        )}
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

          {/* ── In-memory notice ─────────────────────────────────────────────── */}
          {!status.redis.connected && (
            <div className="border border-border rounded-xl p-5 bg-muted/20">
              <div className="flex items-start gap-3">
                <WifiOff className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                <div className="space-y-1 flex-1">
                  <p className="text-sm font-medium">BullMQ job inspector not available in in-memory mode</p>
                  <p className="text-xs text-muted-foreground leading-relaxed">
                    Individual job history requires Redis. Queue stats above reflect the in-process FIFO
                    queue directly. Pause/Resume and Kill actions require Redis mode.
                    Set <code className="font-mono bg-muted px-1 rounded">REDIS_URL</code> in environment secrets.
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
