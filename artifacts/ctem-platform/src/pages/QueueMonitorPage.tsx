import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Activity, CheckCircle2, XCircle, Clock, Pause, RefreshCw, Layers, Wifi, WifiOff, AlertTriangle, RotateCcw } from "lucide-react";
import { getToken } from "@/lib/auth";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { useToast } from "@/hooks/use-toast";

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
    method: "POST",
    headers: headers(),
    body: JSON.stringify({ queue }),
  });
  if (!res.ok) throw new Error("Failed to retry jobs");
  return res.json();
}

function StatCard({ label, value, icon: Icon, color }: { label: string; value: number; icon: React.ElementType; color: string }) {
  return (
    <div className="bg-card border border-border rounded-lg p-4 flex items-center gap-3">
      <div className={`w-9 h-9 rounded-lg flex items-center justify-center ${color}`}>
        <Icon className="w-4 h-4" />
      </div>
      <div>
        <p className="text-xl font-bold">{value}</p>
        <p className="text-xs text-muted-foreground">{label}</p>
      </div>
    </div>
  );
}

function QueuePanel({ stat, queueName, selectedQueue, setSelectedQueue }: {
  stat: QueueStat;
  queueName: string;
  selectedQueue: string;
  setSelectedQueue: (q: string) => void;
}) {
  const isSelected = selectedQueue === queueName;
  return (
    <div
      className={`border rounded-xl p-5 cursor-pointer transition-all ${isSelected ? "border-primary/50 bg-primary/5" : "border-border bg-card hover:border-border/80"}`}
      onClick={() => setSelectedQueue(queueName)}
    >
      <div className="flex items-center justify-between mb-4">
        <div>
          <p className="font-semibold text-sm">{stat.name}</p>
          {stat.paused && <Badge variant="secondary" className="mt-1 text-[10px]">PAUSED</Badge>}
        </div>
        <Layers className="w-4 h-4 text-muted-foreground" />
      </div>
      <div className="grid grid-cols-2 gap-2 text-sm">
        <div className="flex items-center gap-2">
          <div className="w-2 h-2 rounded-full bg-blue-500 animate-pulse" />
          <span className="text-muted-foreground">Active</span>
          <span className="ml-auto font-medium">{stat.active}</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="w-2 h-2 rounded-full bg-yellow-500" />
          <span className="text-muted-foreground">Waiting</span>
          <span className="ml-auto font-medium">{stat.waiting}</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="w-2 h-2 rounded-full bg-green-500" />
          <span className="text-muted-foreground">Completed</span>
          <span className="ml-auto font-medium">{stat.completed}</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="w-2 h-2 rounded-full bg-red-500" />
          <span className="text-muted-foreground">Failed</span>
          <span className="ml-auto font-medium">{stat.failed}</span>
        </div>
        <div className="flex items-center gap-2 col-span-2">
          <div className="w-2 h-2 rounded-full bg-purple-500" />
          <span className="text-muted-foreground">Delayed</span>
          <span className="ml-auto font-medium">{stat.delayed}</span>
        </div>
      </div>
    </div>
  );
}

function JobRow({ job }: { job: Job }) {
  const duration = job.finishedOn && job.processedOn
    ? `${((job.finishedOn - job.processedOn) / 1000).toFixed(1)}s`
    : null;

  return (
    <div className="border border-border rounded-lg p-3 text-sm">
      <div className="flex items-center justify-between mb-2">
        <span className="font-mono text-xs text-muted-foreground">#{job.id}</span>
        <div className="flex items-center gap-2">
          {job.attemptsMade > 1 && (
            <Badge variant="outline" className="text-[10px]">{job.attemptsMade} attempts</Badge>
          )}
          <span className="text-xs text-muted-foreground">
            {new Date(job.timestamp).toLocaleTimeString()}
          </span>
        </div>
      </div>
      <p className="font-medium truncate mb-1">{job.name}</p>
      {job.failedReason && (
        <p className="text-xs text-red-400 bg-red-500/10 rounded px-2 py-1 mt-1 truncate">
          {job.failedReason}
        </p>
      )}
      {duration && <p className="text-xs text-muted-foreground mt-1">Duration: {duration}</p>}
      {typeof job.progress === "number" && job.progress > 0 && (
        <div className="mt-2 h-1 bg-muted rounded-full overflow-hidden">
          <div className="h-full bg-primary rounded-full transition-all" style={{ width: `${job.progress}%` }} />
        </div>
      )}
    </div>
  );
}

export default function QueueMonitorPage() {
  const [selectedQueue, setSelectedQueue] = useState("scans");
  const [jobType, setJobType] = useState<"active" | "waiting" | "completed" | "failed" | "delayed">("active");
  const qc = useQueryClient();
  const { toast } = useToast();

  const { data: status, isLoading } = useQuery({
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

  return (
    <div className="p-6 max-w-5xl mx-auto space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Queue Monitor</h1>
          <p className="text-sm text-muted-foreground mt-0.5">BullMQ job queue status (Celery equivalent)</p>
        </div>
        <Button variant="outline" size="sm" onClick={() => qc.invalidateQueries()}>
          <RefreshCw className="w-3.5 h-3.5 mr-2" />
          Refresh
        </Button>
      </div>

      {isLoading ? (
        <div className="text-center py-12 text-muted-foreground">Loading queue status…</div>
      ) : status ? (
        <>
          <div className={`flex items-center gap-3 p-4 rounded-xl border ${status.redis.connected ? "border-green-500/20 bg-green-500/5" : "border-yellow-500/20 bg-yellow-500/5"}`}>
            {status.redis.connected
              ? <Wifi className="w-5 h-5 text-green-400" />
              : <WifiOff className="w-5 h-5 text-yellow-400" />}
            <div>
              <p className="font-medium text-sm">
                {status.redis.connected
                  ? "Redis connected — BullMQ workers active"
                  : "Redis not configured — using in-memory fallback"}
              </p>
              <p className="text-xs text-muted-foreground">
                Mode: <span className="font-mono">{status.mode}</span>
                {" · "}URL: <span className="font-mono">{status.redis.url}</span>
                {" · "}Set <span className="font-mono">REDIS_URL</span> env var to enable distributed queues
              </p>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <QueuePanel
              stat={status.queues.scans}
              queueName="scans"
              selectedQueue={selectedQueue}
              setSelectedQueue={setSelectedQueue}
            />
            <QueuePanel
              stat={status.queues.alerts}
              queueName="alerts"
              selectedQueue={selectedQueue}
              setSelectedQueue={setSelectedQueue}
            />
          </div>

          {status.redis.connected && (
            <>
              <div className="flex items-center justify-between">
                <div className="flex gap-1 bg-muted/50 rounded-lg p-1">
                  {JOB_TYPES.map((t) => (
                    <button
                      key={t}
                      onClick={() => setJobType(t)}
                      className={`px-3 py-1.5 text-xs font-medium rounded-md capitalize transition-colors ${jobType === t ? "bg-background text-foreground shadow-sm" : "text-muted-foreground hover:text-foreground"}`}
                    >
                      {t}
                      {t === "failed" && status.queues[selectedQueue as "scans" | "alerts"]?.failed > 0 && (
                        <span className="ml-1 text-red-400">({status.queues[selectedQueue as "scans" | "alerts"].failed})</span>
                      )}
                    </button>
                  ))}
                </div>
                {jobType === "failed" && (
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => retryMutation.mutate()}
                    disabled={retryMutation.isPending}
                  >
                    <RotateCcw className="w-3.5 h-3.5 mr-2" />
                    Retry All Failed
                  </Button>
                )}
              </div>

              <div className="space-y-2">
                {jobsLoading && <div className="text-center py-8 text-muted-foreground">Loading jobs…</div>}
                {!jobsLoading && jobsData?.jobs.length === 0 && (
                  <div className="text-center py-8 text-muted-foreground border border-border rounded-xl">
                    No {jobType} jobs in the <span className="font-mono">{selectedQueue}</span> queue
                  </div>
                )}
                {!jobsLoading && jobsData?.jobs.map((job) => (
                  <JobRow key={job.id} job={job} />
                ))}
              </div>
            </>
          )}

          {!status.redis.connected && (
            <div className="border border-border rounded-xl p-6 text-center space-y-3">
              <AlertTriangle className="w-8 h-8 text-yellow-400 mx-auto" />
              <p className="font-medium">In-memory mode active</p>
              <p className="text-sm text-muted-foreground max-w-md mx-auto">
                Jobs run in-process and are not persisted. To enable distributed queuing with retry logic,
                persistence and real-time monitoring, set the <span className="font-mono bg-muted px-1 rounded">REDIS_URL</span> environment variable
                to an Upstash Redis or self-hosted Redis URL.
              </p>
              <div className="text-xs text-muted-foreground font-mono bg-muted rounded-lg p-3 text-left max-w-sm mx-auto">
                REDIS_URL=redis://default:&lt;password&gt;@&lt;host&gt;:6379
              </div>
            </div>
          )}
        </>
      ) : (
        <div className="text-center py-12 text-muted-foreground">Failed to load queue status</div>
      )}
    </div>
  );
}
