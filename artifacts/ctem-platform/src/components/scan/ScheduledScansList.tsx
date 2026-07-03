import { useState } from "react";
import {
  useListScanSchedules, useDeleteScanSchedule, useUpdateScanSchedule, useRunScheduleNow,
  useListAssetGroups, getListScanSchedulesQueryKey, getListAssetGroupsQueryKey,
} from "@workspace/api-client-react";
import { useQueryClient } from "@tanstack/react-query";
import { useLocation } from "wouter";
import {
  Calendar, Play, Trash2, Pause, Play as Resume, Edit2, RefreshCw,
  Clock, CheckCircle2, AlertTriangle, Layers,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";

const DAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const DAYS_FULL = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];

const TIMEZONES = [
  { label: "UTC ±00:00",             value: "+00:00" },
  { label: "US/Eastern  UTC-05:00",  value: "-05:00" },
  { label: "US/Central  UTC-06:00",  value: "-06:00" },
  { label: "US/Mountain UTC-07:00",  value: "-07:00" },
  { label: "US/Pacific  UTC-08:00",  value: "-08:00" },
  { label: "US/Alaska   UTC-09:00",  value: "-09:00" },
  { label: "US/Hawaii   UTC-10:00",  value: "-10:00" },
  { label: "Europe/London UTC+00:00",value: "+00:00" },
  { label: "Europe/Paris UTC+01:00", value: "+01:00" },
  { label: "Europe/Berlin UTC+01:00",value: "+01:00" },
  { label: "Europe/Athens UTC+02:00",value: "+02:00" },
  { label: "Europe/Moscow UTC+03:00",value: "+03:00" },
  { label: "Asia/Dubai  UTC+04:00",  value: "+04:00" },
  { label: "Asia/Karachi UTC+05:00", value: "+05:00" },
  { label: "Asia/Kolkata UTC+05:30", value: "+05:30" },
  { label: "Asia/Dhaka  UTC+06:00",  value: "+06:00" },
  { label: "Asia/Bangkok UTC+07:00", value: "+07:00" },
  { label: "Asia/Shanghai UTC+08:00",value: "+08:00" },
  { label: "Asia/Tokyo  UTC+09:00",  value: "+09:00" },
  { label: "Australia/Sydney UTC+10:00", value: "+10:00" },
  { label: "Pacific/Auckland UTC+12:00", value: "+12:00" },
];

function frequencyLabel(s: { frequency: string; runTime: string; dayOfWeek?: number | null; dayOfMonth?: number | null; timezone?: string | null }) {
  const t = s.runTime;
  const tz = s.timezone && s.timezone !== "+00:00" ? ` (UTC${s.timezone})` : " UTC";
  if (s.frequency === "daily") return `Daily at ${t}${tz}`;
  if (s.frequency === "weekly") return `Weekly on ${DAYS_FULL[s.dayOfWeek ?? 1]} at ${t}${tz}`;
  if (s.frequency === "monthly") return `Monthly on day ${s.dayOfMonth ?? 1} at ${t}${tz}`;
  return `Once at ${t}${tz}`;
}

function nextRunLabel(nextRunAt: string | null) {
  if (!nextRunAt) return "—";
  const d = new Date(nextRunAt);
  const now = new Date();
  const diffMs = d.getTime() - now.getTime();
  if (diffMs < 0) return "Overdue";
  const diffH = Math.floor(diffMs / 3600000);
  if (diffH < 24) return `In ${diffH}h ${Math.floor((diffMs % 3600000) / 60000)}m`;
  const diffD = Math.floor(diffH / 24);
  return `In ${diffD} day${diffD !== 1 ? "s" : ""}`;
}

export default function ScheduledScansList({ onRefetchNeeded }: { onRefetchNeeded?: () => void }) {
  const qc = useQueryClient();
  const [, navigate] = useLocation();
  const [editSchedule, setEditSchedule] = useState<any | null>(null);
  const [editForm, setEditForm] = useState({ name: "", frequency: "daily", runTime: "09:00", dayOfWeek: 1, dayOfMonth: 1, timezone: "+00:00" });
  const [runningId, setRunningId] = useState<number | null>(null);

  const { data: schedulesData, isLoading } = useListScanSchedules({
    query: { queryKey: getListScanSchedulesQueryKey() },
  });
  const schedules = (schedulesData as any[]) ?? [];

  const { data: groupsData } = useListAssetGroups({ query: { queryKey: getListAssetGroupsQueryKey() } });
  const groupMap = new Map<number, string>(
    ((groupsData as any[]) ?? []).map((g: any) => [g.id, g.name])
  );

  const deleteMutation = useDeleteScanSchedule();
  const updateMutation = useUpdateScanSchedule();
  const runNowMutation = useRunScheduleNow();

  async function handleDelete(id: number) {
    if (!confirm("Delete this schedule? This won't affect past scan results.")) return;
    await deleteMutation.mutateAsync({ scheduleId: id });
    qc.invalidateQueries({ queryKey: getListScanSchedulesQueryKey() });
  }

  async function handleTogglePause(schedule: any) {
    const newStatus = schedule.status === "active" ? "paused" : "active";
    await updateMutation.mutateAsync({ scheduleId: schedule.id, data: { status: newStatus } as any });
    qc.invalidateQueries({ queryKey: getListScanSchedulesQueryKey() });
  }

  async function handleRunNow(scheduleId: number) {
    setRunningId(scheduleId);
    try {
      const result = await runNowMutation.mutateAsync({ scheduleId });
      qc.invalidateQueries({ queryKey: getListScanSchedulesQueryKey() });
      navigate(`/scan-reports/${(result as any).scanId}`);
    } finally {
      setRunningId(null);
    }
  }

  function openEdit(schedule: any) {
    setEditSchedule(schedule);
    setEditForm({
      name: schedule.name,
      frequency: schedule.frequency,
      runTime: schedule.runTime,
      dayOfWeek: schedule.dayOfWeek ?? 1,
      dayOfMonth: schedule.dayOfMonth ?? 1,
      timezone: schedule.timezone ?? "+00:00",
    });
  }

  async function handleSaveEdit() {
    if (!editSchedule) return;
    const payload: Record<string, unknown> = {
      name: editForm.name,
      frequency: editForm.frequency,
      runTime: editForm.runTime,
      timezone: editForm.timezone,
    };
    if (editForm.frequency === "weekly") payload.dayOfWeek = editForm.dayOfWeek;
    if (editForm.frequency === "monthly") payload.dayOfMonth = editForm.dayOfMonth;
    await updateMutation.mutateAsync({ scheduleId: editSchedule.id, data: payload as any });
    qc.invalidateQueries({ queryKey: getListScanSchedulesQueryKey() });
    setEditSchedule(null);
  }

  if (isLoading) return <div className="space-y-2">{[...Array(2)].map((_, i) => <Skeleton key={i} className="h-16 rounded-lg" />)}</div>;

  if (schedules.length === 0) return null;

  return (
    <>
      <div className="bg-card border border-border rounded-xl overflow-hidden">
        <div className="flex items-center justify-between px-4 py-3 border-b border-border">
          <div className="flex items-center gap-2">
            <Calendar className="w-4 h-4 text-primary" />
            <h3 className="text-sm font-medium">Scheduled Scans</h3>
            <span className="text-[10px] bg-primary/15 text-primary px-1.5 py-0.5 rounded-full">{schedules.length}</span>
          </div>
          <Button variant="ghost" size="sm" className="h-7 px-2 text-xs text-muted-foreground"
            onClick={() => qc.invalidateQueries({ queryKey: getListScanSchedulesQueryKey() })}>
            <RefreshCw className="w-3 h-3 mr-1" /> Refresh
          </Button>
        </div>

        <div className="divide-y divide-border/50">
          {schedules.map((schedule: any) => {
            const assetCount = Array.isArray(schedule.assetToolConfig) ? schedule.assetToolConfig.length : 0;
            const isRunning = runningId === schedule.id;

            return (
              <div key={schedule.id} className="flex items-center gap-3 px-4 py-3">
                <div className={cn("w-2 h-2 rounded-full shrink-0", schedule.status === "active" ? "bg-green-400" : "bg-muted-foreground")} />

                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <p className="text-sm font-medium truncate">{schedule.name}</p>
                    <span className={cn("text-[10px] px-1.5 py-0.5 rounded border shrink-0",
                      schedule.status === "active"
                        ? "bg-green-500/10 text-green-400 border-green-500/25"
                        : "bg-muted text-muted-foreground border-border")}>
                      {schedule.status}
                    </span>
                    {schedule.groupId && groupMap.has(schedule.groupId) && (
                      <span className="flex items-center gap-0.5 text-[10px] px-1.5 py-0.5 rounded border bg-primary/10 text-primary border-primary/25 shrink-0">
                        <Layers className="w-2.5 h-2.5" />
                        {groupMap.get(schedule.groupId)}
                      </span>
                    )}
                  </div>
                  <div className="flex items-center gap-3 mt-0.5 text-[10px] text-muted-foreground">
                    <span className="flex items-center gap-1">
                      <Clock className="w-2.5 h-2.5" />
                      {frequencyLabel(schedule)}
                    </span>
                    {!schedule.groupId && <span>{assetCount} asset{assetCount !== 1 ? "s" : ""}</span>}
                    {schedule.nextRunAt && (
                      <span className="flex items-center gap-1 text-blue-400">
                        <CheckCircle2 className="w-2.5 h-2.5" />
                        Next: {nextRunLabel(schedule.nextRunAt)}
                      </span>
                    )}
                    {schedule.lastRunAt && (
                      <span>Last run: {new Date(schedule.lastRunAt).toLocaleDateString()}</span>
                    )}
                  </div>
                </div>

                {/* Actions */}
                <div className="flex items-center gap-1 shrink-0">
                  <Button
                    variant="ghost" size="sm"
                    className="h-7 px-2 text-xs text-green-500 hover:text-green-400 hover:bg-green-500/10"
                    onClick={() => handleRunNow(schedule.id)}
                    disabled={isRunning}
                  >
                    {isRunning ? <div className="w-3.5 h-3.5 border-2 border-green-500 border-t-transparent rounded-full animate-spin" /> : <Play className="w-3.5 h-3.5" />}
                  </Button>

                  <Button variant="ghost" size="sm" className="h-7 px-2 text-xs text-muted-foreground hover:text-foreground" onClick={() => openEdit(schedule)}>
                    <Edit2 className="w-3.5 h-3.5" />
                  </Button>

                  <Button
                    variant="ghost" size="sm"
                    className={cn("h-7 px-2 text-xs", schedule.status === "active" ? "text-amber-500 hover:text-amber-400 hover:bg-amber-500/10" : "text-muted-foreground hover:text-foreground")}
                    onClick={() => handleTogglePause(schedule)}
                  >
                    {schedule.status === "active" ? <Pause className="w-3.5 h-3.5" /> : <Resume className="w-3.5 h-3.5" />}
                  </Button>

                  <Button variant="ghost" size="sm" className="h-7 px-2 text-xs text-destructive hover:text-red-400" onClick={() => handleDelete(schedule.id)}>
                    <Trash2 className="w-3.5 h-3.5" />
                  </Button>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Edit Dialog */}
      <Dialog open={!!editSchedule} onOpenChange={o => { if (!o) setEditSchedule(null); }}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Edit2 className="w-4 h-4 text-primary" /> Edit Schedule
            </DialogTitle>
          </DialogHeader>

          <div className="space-y-4">
            <div>
              <Label className="text-xs mb-1.5 block">Schedule Name</Label>
              <Input value={editForm.name} onChange={e => setEditForm(p => ({ ...p, name: e.target.value }))} className="text-sm" />
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <Label className="text-xs mb-1.5 block">Frequency</Label>
                <Select value={editForm.frequency} onValueChange={v => setEditForm(p => ({ ...p, frequency: v }))}>
                  <SelectTrigger className="text-sm h-9"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="daily">Daily</SelectItem>
                    <SelectItem value="weekly">Weekly</SelectItem>
                    <SelectItem value="monthly">Monthly</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div>
                <Label className="text-xs mb-1.5 block flex items-center gap-1"><Clock className="w-3 h-3" /> Time</Label>
                <Input type="time" value={editForm.runTime} onChange={e => setEditForm(p => ({ ...p, runTime: e.target.value }))} className="text-sm h-9" />
              </div>
            </div>

            {editForm.frequency === "weekly" && (
              <div>
                <Label className="text-xs mb-1.5 block">Day of Week</Label>
                <Select value={String(editForm.dayOfWeek)} onValueChange={v => setEditForm(p => ({ ...p, dayOfWeek: Number(v) }))}>
                  <SelectTrigger className="text-sm h-9"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {DAYS_FULL.map((d, i) => <SelectItem key={i} value={String(i)}>{d}</SelectItem>)}
                  </SelectContent>
                </Select>
              </div>
            )}

            {editForm.frequency === "monthly" && (
              <div>
                <Label className="text-xs mb-1.5 block">Day of Month</Label>
                <Select value={String(editForm.dayOfMonth)} onValueChange={v => setEditForm(p => ({ ...p, dayOfMonth: Number(v) }))}>
                  <SelectTrigger className="text-sm h-9"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {Array.from({ length: 28 }, (_, i) => i + 1).map(d => (
                      <SelectItem key={d} value={String(d)}>{d}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            )}

            <div>
              <Label className="text-xs mb-1.5 block">Timezone</Label>
              <Select value={editForm.timezone} onValueChange={v => setEditForm(p => ({ ...p, timezone: v }))}>
                <SelectTrigger className="text-sm h-9"><SelectValue /></SelectTrigger>
                <SelectContent>
                  {[...new Map(TIMEZONES.map(tz => [tz.value, tz])).values()].map(tz => (
                    <SelectItem key={tz.value} value={tz.value}>{tz.label}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <p className="text-[10px] text-muted-foreground mt-1">Run time is interpreted in this timezone</p>
            </div>

            {editSchedule && (
              <div className="bg-accent/30 rounded-lg px-3 py-2 text-xs text-muted-foreground flex items-center gap-2">
                <AlertTriangle className="w-3 h-3 text-amber-400 shrink-0" />
                Asset & tool selection can only be changed by creating a new schedule.
              </div>
            )}
          </div>

          <DialogFooter>
            <Button variant="outline" onClick={() => setEditSchedule(null)}>Cancel</Button>
            <Button onClick={handleSaveEdit} disabled={updateMutation.isPending}>
              {updateMutation.isPending ? "Saving…" : "Save Changes"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
