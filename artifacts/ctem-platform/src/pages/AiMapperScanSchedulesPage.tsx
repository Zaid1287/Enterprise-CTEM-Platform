import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { apiFetch } from "@/lib/apiFetch";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { Switch } from "@/components/ui/switch";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog";
import { CalendarClock, Plus, Pencil, Trash2, Play, Loader2, Clock } from "lucide-react";

interface Schedule {
  id: number;
  tenantId: number;
  title: string;
  frequency: string;
  nextRunAt: string;
  lastRunAt: string | null;
  lastScanId: number | null;
  isActive: boolean;
  cidrScope: string | null;
  queryPresets: string[];
  createdAt: string;
}

const FREQ_LABELS: Record<string, string> = {
  hourly: "Every Hour",
  daily: "Every Day",
  weekly: "Every Week",
  monthly: "Every Month",
};

function fmt(iso: string | null | undefined) {
  if (!iso) return "—";
  return new Date(iso).toLocaleString();
}

function ScheduleForm({
  initial,
  onSave,
  onClose,
  loading,
}: {
  initial?: Partial<Schedule>;
  onSave: (data: Partial<Schedule>) => void;
  onClose: () => void;
  loading: boolean;
}) {
  const [title, setTitle] = useState(initial?.title ?? "Scheduled AI Scan");
  const [frequency, setFrequency] = useState(initial?.frequency ?? "daily");
  const [cidrScope, setCidrScope] = useState(initial?.cidrScope ?? "");
  const [isActive, setIsActive] = useState(initial?.isActive ?? true);

  return (
    <div className="space-y-4">
      <div className="space-y-1">
        <Label>Title</Label>
        <Input value={title} onChange={e => setTitle(e.target.value)} placeholder="Scheduled AI Surface Scan" />
      </div>
      <div className="space-y-1">
        <Label>Frequency</Label>
        <Select value={frequency} onValueChange={setFrequency}>
          <SelectTrigger><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem value="hourly">Every Hour</SelectItem>
            <SelectItem value="daily">Every Day</SelectItem>
            <SelectItem value="weekly">Every Week</SelectItem>
            <SelectItem value="monthly">Every Month</SelectItem>
          </SelectContent>
        </Select>
      </div>
      <div className="space-y-1">
        <Label>CIDR Scope <span className="text-muted-foreground text-xs">(optional — leave blank to scan asset inventory)</span></Label>
        <Input
          value={cidrScope}
          onChange={e => setCidrScope(e.target.value)}
          placeholder="e.g. 10.0.0.0/24, 192.168.1.50"
          className="font-mono text-sm"
        />
      </div>
      <div className="flex items-center gap-2">
        <Switch checked={isActive} onCheckedChange={setIsActive} id="active-switch" />
        <Label htmlFor="active-switch">Active</Label>
      </div>
      <DialogFooter>
        <Button variant="outline" onClick={onClose} disabled={loading}>Cancel</Button>
        <Button onClick={() => onSave({ title, frequency, cidrScope: cidrScope.trim() || null, isActive })} disabled={loading || !title.trim()}>
          {loading ? <><Loader2 className="w-4 h-4 mr-2 animate-spin" />Saving…</> : "Save Schedule"}
        </Button>
      </DialogFooter>
    </div>
  );
}

export default function AiMapperScanSchedulesPage() {
  const qc = useQueryClient();
  const [showCreate, setShowCreate] = useState(false);
  const [editTarget, setEditTarget] = useState<Schedule | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<Schedule | null>(null);

  const { data: schedules = [], isLoading } = useQuery<Schedule[]>({
    queryKey: ["ai-mapper-schedules"],
    queryFn: () => apiFetch("/api/ai-mapper/scan-schedules"),
    refetchInterval: 30_000,
  });

  const invalidate = () => qc.invalidateQueries({ queryKey: ["ai-mapper-schedules"] });

  const createMut = useMutation({
    mutationFn: (data: Partial<Schedule>) => apiFetch("/api/ai-mapper/scan-schedules", { method: "POST", body: JSON.stringify(data) }),
    onSuccess: () => { invalidate(); setShowCreate(false); },
  });

  const updateMut = useMutation({
    mutationFn: (data: Partial<Schedule>) => apiFetch(`/api/ai-mapper/scan-schedules/${editTarget!.id}`, { method: "PATCH", body: JSON.stringify(data) }),
    onSuccess: () => { invalidate(); setEditTarget(null); },
  });

  const deleteMut = useMutation({
    mutationFn: (id: number) => apiFetch(`/api/ai-mapper/scan-schedules/${id}`, { method: "DELETE" }),
    onSuccess: () => { invalidate(); setDeleteTarget(null); },
  });

  const toggleMut = useMutation({
    mutationFn: ({ id, isActive }: { id: number; isActive: boolean }) =>
      apiFetch(`/api/ai-mapper/scan-schedules/${id}`, { method: "PATCH", body: JSON.stringify({ isActive }) }),
    onSuccess: invalidate,
  });

  return (
    <div className="p-6 space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <CalendarClock className="w-6 h-6 text-indigo-400" />
            <div>
              <h1 className="text-2xl font-bold text-white">Scan Schedules</h1>
              <p className="text-sm text-muted-foreground">Automate AI surface scans on a recurring schedule</p>
            </div>
          </div>
          <Button onClick={() => setShowCreate(true)}>
            <Plus className="w-4 h-4 mr-2" /> New Schedule
          </Button>
        </div>

        {/* List */}
        {isLoading ? (
          <div className="flex items-center justify-center h-40 text-muted-foreground">
            <Loader2 className="w-6 h-6 animate-spin mr-2" /> Loading schedules…
          </div>
        ) : schedules.length === 0 ? (
          <Card className="bg-card/60 border-border/40">
            <CardContent className="flex flex-col items-center justify-center py-16 text-center gap-3">
              <CalendarClock className="w-12 h-12 text-muted-foreground/40" />
              <p className="text-muted-foreground">No scan schedules yet. Create one to automate recurring AI surface scans.</p>
              <Button variant="outline" onClick={() => setShowCreate(true)}>
                <Plus className="w-4 h-4 mr-2" /> Create First Schedule
              </Button>
            </CardContent>
          </Card>
        ) : (
          <div className="grid gap-4">
            {schedules.map(sch => (
              <Card key={sch.id} className={`bg-card/60 border-border/40 transition-opacity ${!sch.isActive ? "opacity-60" : ""}`}>
                <CardHeader className="pb-2">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <CardTitle className="text-base font-semibold text-white">{sch.title}</CardTitle>
                      <Badge variant={sch.isActive ? "default" : "secondary"} className="text-xs">
                        {sch.isActive ? "Active" : "Paused"}
                      </Badge>
                      <Badge variant="outline" className="text-xs">
                        <Clock className="w-3 h-3 mr-1" />{FREQ_LABELS[sch.frequency] ?? sch.frequency}
                      </Badge>
                    </div>
                    <div className="flex items-center gap-2">
                      <Switch
                        checked={sch.isActive}
                        onCheckedChange={v => toggleMut.mutate({ id: sch.id, isActive: v })}
                      />
                      <Button size="icon" variant="ghost" onClick={() => setEditTarget(sch)}>
                        <Pencil className="w-4 h-4" />
                      </Button>
                      <Button size="icon" variant="ghost" className="text-destructive hover:text-destructive" onClick={() => setDeleteTarget(sch)}>
                        <Trash2 className="w-4 h-4" />
                      </Button>
                    </div>
                  </div>
                </CardHeader>
                <CardContent className="text-sm text-muted-foreground grid grid-cols-2 md:grid-cols-4 gap-3">
                  <div>
                    <p className="text-xs uppercase tracking-wide text-muted-foreground/60 mb-1">Next Run</p>
                    <p className="text-white/80">{fmt(sch.nextRunAt)}</p>
                  </div>
                  <div>
                    <p className="text-xs uppercase tracking-wide text-muted-foreground/60 mb-1">Last Run</p>
                    <p className="text-white/80">{fmt(sch.lastRunAt)}</p>
                  </div>
                  <div>
                    <p className="text-xs uppercase tracking-wide text-muted-foreground/60 mb-1">CIDR Scope</p>
                    <p className="font-mono text-xs text-white/80">{sch.cidrScope || "Asset inventory"}</p>
                  </div>
                  <div>
                    <p className="text-xs uppercase tracking-wide text-muted-foreground/60 mb-1">Last Scan ID</p>
                    <p className="font-mono text-white/80">{sch.lastScanId ?? "—"}</p>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        )}

        {/* Create Dialog */}
        <Dialog open={showCreate} onOpenChange={setShowCreate}>
          <DialogContent>
            <DialogHeader><DialogTitle>Create Scan Schedule</DialogTitle></DialogHeader>
            <ScheduleForm
              onSave={d => createMut.mutate(d)}
              onClose={() => setShowCreate(false)}
              loading={createMut.isPending}
            />
          </DialogContent>
        </Dialog>

        {/* Edit Dialog */}
        <Dialog open={!!editTarget} onOpenChange={o => !o && setEditTarget(null)}>
          <DialogContent>
            <DialogHeader><DialogTitle>Edit Schedule</DialogTitle></DialogHeader>
            {editTarget && (
              <ScheduleForm
                initial={editTarget}
                onSave={d => updateMut.mutate(d)}
                onClose={() => setEditTarget(null)}
                loading={updateMut.isPending}
              />
            )}
          </DialogContent>
        </Dialog>

        {/* Delete Confirm Dialog */}
        <Dialog open={!!deleteTarget} onOpenChange={o => !o && setDeleteTarget(null)}>
          <DialogContent>
            <DialogHeader><DialogTitle>Delete Schedule</DialogTitle></DialogHeader>
            <p className="text-muted-foreground text-sm">
              Are you sure you want to delete <span className="text-white font-medium">"{deleteTarget?.title}"</span>? This cannot be undone.
            </p>
            <DialogFooter>
              <Button variant="outline" onClick={() => setDeleteTarget(null)}>Cancel</Button>
              <Button variant="destructive" onClick={() => deleteMut.mutate(deleteTarget!.id)} disabled={deleteMut.isPending}>
                {deleteMut.isPending ? <Loader2 className="w-4 h-4 animate-spin mr-2" /> : <Trash2 className="w-4 h-4 mr-2" />}
                Delete
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
    </div>
  );
}
