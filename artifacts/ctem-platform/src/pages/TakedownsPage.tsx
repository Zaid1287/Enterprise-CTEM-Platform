import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { apiFetch } from "@/lib/apiFetch";
import { cn } from "@/lib/utils";
import {
  ShieldOff, Globe, Flag, AlertTriangle, CheckCircle2,
  Clock, XCircle, Plus, ChevronRight, Loader2,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import { useToast } from "@/hooks/use-toast";

const BASE = import.meta.env.BASE_URL.replace(/\/$/, "");

const TYPE_LABELS: Record<string, string> = {
  phishing: "Phishing Page",
  brand_impersonation: "Brand Impersonation",
  domain_squatting: "Domain Squatting",
  fake_social: "Fake Social Media",
  malware_hosting: "Malware Hosting",
  other: "Other",
};

const STATUS_CONFIG: Record<string, { label: string; color: string; icon: React.ElementType }> = {
  submitted:   { label: "Submitted",    color: "bg-blue-500/15 text-blue-400 border-blue-500/30",   icon: Clock },
  in_progress: { label: "In Progress",  color: "bg-amber-500/15 text-amber-400 border-amber-500/30", icon: Loader2 },
  closed:      { label: "Closed",       color: "bg-green-500/15 text-green-400 border-green-500/30", icon: CheckCircle2 },
  rejected:    { label: "Rejected",     color: "bg-red-500/15 text-red-400 border-red-500/30",       icon: XCircle },
};

const PRIORITY_CONFIG: Record<string, { color: string }> = {
  critical: { color: "bg-red-500/15 text-red-400 border-red-500/30" },
  high:     { color: "bg-orange-500/15 text-orange-400 border-orange-500/30" },
  medium:   { color: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30" },
  low:      { color: "bg-muted text-muted-foreground border-border" },
};

function StatusBadge({ status }: { status: string }) {
  const cfg = STATUS_CONFIG[status] ?? STATUS_CONFIG.submitted;
  const Icon = cfg.icon;
  return (
    <span className={cn("inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded-md font-medium border", cfg.color)}>
      <Icon className="w-3 h-3" />
      {cfg.label}
    </span>
  );
}

function PriorityBadge({ priority }: { priority: string }) {
  const cfg = PRIORITY_CONFIG[priority] ?? PRIORITY_CONFIG.medium;
  return (
    <span className={cn("text-xs px-2 py-0.5 rounded-md font-medium border capitalize", cfg.color)}>
      {priority}
    </span>
  );
}

export default function TakedownsPage() {
  const qc = useQueryClient();
  const { toast } = useToast();
  const [showNew, setShowNew] = useState(false);
  const [selected, setSelected] = useState<any>(null);
  const [form, setForm] = useState({
    type: "phishing", targetUrl: "", targetDomain: "", hostingProvider: "",
    registrar: "", title: "", description: "", brandAbused: "", priority: "high",
  });

  const { data: requests = [], isLoading } = useQuery<any[]>({
    queryKey: ["takedowns"],
    queryFn: () => apiFetch(`${BASE}/api/takedowns`),
  });

  const createMutation = useMutation({
    mutationFn: (body: any) =>
      apiFetch(`${BASE}/api/takedowns`, { method: "POST", body: JSON.stringify(body) }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["takedowns"] });
      setShowNew(false);
      setForm({ type: "phishing", targetUrl: "", targetDomain: "", hostingProvider: "",
        registrar: "", title: "", description: "", brandAbused: "", priority: "high" });
      toast({ title: "Takedown request submitted" });
    },
    onError: () => toast({ title: "Failed to submit request", variant: "destructive" }),
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, ...body }: any) =>
      apiFetch(`${BASE}/api/takedowns/${id}`, { method: "PATCH", body: JSON.stringify(body) }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["takedowns"] });
      setSelected(null);
      toast({ title: "Request updated" });
    },
  });

  // Summary counts
  const total = requests.length;
  const submitted = requests.filter(r => r.status === "submitted").length;
  const inProgress = requests.filter(r => r.status === "in_progress").length;
  const closed = requests.filter(r => r.status === "closed").length;
  const rejected = requests.filter(r => r.status === "rejected").length;

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold">Takedown Requests</h1>
          <p className="text-sm text-muted-foreground">
            Manage phishing, brand impersonation, domain squatting & abuse takedowns
          </p>
        </div>
        <Button size="sm" onClick={() => setShowNew(true)}>
          <Plus className="w-4 h-4 mr-1.5" />
          New Request
        </Button>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        {[
          { label: "Total",       value: total,      color: "text-foreground",    icon: ShieldOff },
          { label: "Submitted",   value: submitted,  color: "text-blue-400",      icon: Clock },
          { label: "In Progress", value: inProgress, color: "text-amber-400",     icon: Loader2 },
          { label: "Closed",      value: closed,     color: "text-green-400",     icon: CheckCircle2 },
          { label: "Rejected",    value: rejected,   color: "text-red-400",       icon: XCircle },
        ].map(({ label, value, color, icon: Icon }) => (
          <div key={label} className="bg-card border border-border rounded-xl p-4">
            <div className="flex items-center justify-between mb-1">
              <p className="text-xs text-muted-foreground">{label}</p>
              <Icon className="w-4 h-4 text-muted-foreground" />
            </div>
            <p className={cn("text-2xl font-bold tabular-nums", color)}>{value}</p>
          </div>
        ))}
      </div>

      {/* Table */}
      <div className="bg-card border border-border rounded-xl overflow-hidden">
        <div className="px-4 py-3 border-b border-border">
          <h3 className="text-sm font-medium">All Requests</h3>
        </div>
        {isLoading ? (
          <div className="flex items-center justify-center py-12">
            <Loader2 className="w-5 h-5 animate-spin text-muted-foreground" />
          </div>
        ) : requests.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-16 text-center">
            <Globe className="w-10 h-10 text-muted-foreground/30 mb-3" />
            <p className="text-sm font-medium text-muted-foreground">No takedown requests yet</p>
            <p className="text-xs text-muted-foreground/60 mt-1">Submit a request to remove phishing pages, impersonating domains, and brand abuse</p>
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Title</th>
                <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Type</th>
                <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground hidden md:table-cell">Target URL</th>
                <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Priority</th>
                <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Status</th>
                <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground hidden lg:table-cell">Submitted</th>
                <th className="px-4 py-2.5" />
              </tr>
            </thead>
            <tbody>
              {requests.map((r: any) => (
                <tr
                  key={r.id}
                  className="border-b border-border/50 hover:bg-accent/30 cursor-pointer"
                  onClick={() => setSelected(r)}
                >
                  <td className="px-4 py-3">
                    <p className="font-medium truncate max-w-[180px]">{r.title}</p>
                    {r.brandAbused && (
                      <p className="text-[10px] text-muted-foreground">Brand: {r.brandAbused}</p>
                    )}
                  </td>
                  <td className="px-4 py-3 text-xs text-muted-foreground">
                    {TYPE_LABELS[r.type] ?? r.type}
                  </td>
                  <td className="px-4 py-3 hidden md:table-cell">
                    <p className="text-xs text-muted-foreground truncate max-w-[200px]">{r.targetUrl}</p>
                  </td>
                  <td className="px-4 py-3"><PriorityBadge priority={r.priority} /></td>
                  <td className="px-4 py-3"><StatusBadge status={r.status} /></td>
                  <td className="px-4 py-3 hidden lg:table-cell text-xs text-muted-foreground">
                    {new Date(r.createdAt).toLocaleDateString()}
                  </td>
                  <td className="px-4 py-3">
                    <ChevronRight className="w-4 h-4 text-muted-foreground" />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* New request dialog */}
      <Dialog open={showNew} onOpenChange={setShowNew}>
        <DialogContent className="max-w-lg max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>New Takedown Request</DialogTitle>
          </DialogHeader>
          <div className="space-y-4 py-2">
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-1.5">
                <Label>Type *</Label>
                <Select value={form.type} onValueChange={v => setForm(f => ({ ...f, type: v }))}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {Object.entries(TYPE_LABELS).map(([v, l]) => (
                      <SelectItem key={v} value={v}>{l}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1.5">
                <Label>Priority</Label>
                <Select value={form.priority} onValueChange={v => setForm(f => ({ ...f, priority: v }))}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="critical">Critical</SelectItem>
                    <SelectItem value="high">High</SelectItem>
                    <SelectItem value="medium">Medium</SelectItem>
                    <SelectItem value="low">Low</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>

            <div className="space-y-1.5">
              <Label>Title *</Label>
              <Input placeholder="e.g. Fake login page impersonating our portal"
                value={form.title} onChange={e => setForm(f => ({ ...f, title: e.target.value }))} />
            </div>

            <div className="space-y-1.5">
              <Label>Target URL *</Label>
              <Input placeholder="https://evil-site.com/phishing"
                value={form.targetUrl} onChange={e => setForm(f => ({ ...f, targetUrl: e.target.value }))} />
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-1.5">
                <Label>Target Domain</Label>
                <Input placeholder="evil-site.com"
                  value={form.targetDomain} onChange={e => setForm(f => ({ ...f, targetDomain: e.target.value }))} />
              </div>
              <div className="space-y-1.5">
                <Label>Brand Abused</Label>
                <Input placeholder="Your brand name"
                  value={form.brandAbused} onChange={e => setForm(f => ({ ...f, brandAbused: e.target.value }))} />
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-1.5">
                <Label>Hosting Provider</Label>
                <Input placeholder="e.g. Cloudflare, AWS"
                  value={form.hostingProvider} onChange={e => setForm(f => ({ ...f, hostingProvider: e.target.value }))} />
              </div>
              <div className="space-y-1.5">
                <Label>Domain Registrar</Label>
                <Input placeholder="e.g. GoDaddy, Namecheap"
                  value={form.registrar} onChange={e => setForm(f => ({ ...f, registrar: e.target.value }))} />
              </div>
            </div>

            <div className="space-y-1.5">
              <Label>Description / Evidence</Label>
              <Textarea placeholder="Describe the abuse, include any supporting evidence (URLs, screenshots, etc.)"
                value={form.description} onChange={e => setForm(f => ({ ...f, description: e.target.value }))}
                rows={4} />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowNew(false)}>Cancel</Button>
            <Button
              disabled={!form.title || !form.targetUrl || createMutation.isPending}
              onClick={() => createMutation.mutate(form)}
            >
              {createMutation.isPending ? <Loader2 className="w-4 h-4 mr-1.5 animate-spin" /> : null}
              Submit Request
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Detail dialog */}
      {selected && (
        <Dialog open={!!selected} onOpenChange={() => setSelected(null)}>
          <DialogContent className="max-w-lg max-h-[90vh] overflow-y-auto">
            <DialogHeader>
              <DialogTitle className="flex items-center gap-2">
                <ShieldOff className="w-4 h-4" />
                {selected.title}
              </DialogTitle>
            </DialogHeader>
            <div className="space-y-4 py-2 text-sm">
              <div className="flex items-center gap-2 flex-wrap">
                <StatusBadge status={selected.status} />
                <PriorityBadge priority={selected.priority} />
                <Badge variant="outline" className="text-xs">{TYPE_LABELS[selected.type] ?? selected.type}</Badge>
              </div>

              <div className="grid grid-cols-2 gap-3 text-sm">
                <div>
                  <p className="text-xs text-muted-foreground mb-0.5">Target URL</p>
                  <p className="font-medium break-all text-xs">{selected.targetUrl}</p>
                </div>
                {selected.targetDomain && (
                  <div>
                    <p className="text-xs text-muted-foreground mb-0.5">Domain</p>
                    <p className="font-medium text-xs">{selected.targetDomain}</p>
                  </div>
                )}
                {selected.brandAbused && (
                  <div>
                    <p className="text-xs text-muted-foreground mb-0.5">Brand Abused</p>
                    <p className="font-medium text-xs">{selected.brandAbused}</p>
                  </div>
                )}
                {selected.hostingProvider && (
                  <div>
                    <p className="text-xs text-muted-foreground mb-0.5">Host Provider</p>
                    <p className="font-medium text-xs">{selected.hostingProvider}</p>
                  </div>
                )}
                {selected.registrar && (
                  <div>
                    <p className="text-xs text-muted-foreground mb-0.5">Registrar</p>
                    <p className="font-medium text-xs">{selected.registrar}</p>
                  </div>
                )}
                <div>
                  <p className="text-xs text-muted-foreground mb-0.5">Submitted</p>
                  <p className="font-medium text-xs">{new Date(selected.createdAt).toLocaleString()}</p>
                </div>
              </div>

              {selected.description && (
                <div>
                  <p className="text-xs text-muted-foreground mb-1">Description / Evidence</p>
                  <p className="text-xs bg-muted/30 rounded-lg p-3 whitespace-pre-wrap">{selected.description}</p>
                </div>
              )}

              {selected.resolutionNote && (
                <div>
                  <p className="text-xs text-muted-foreground mb-1">Resolution Note</p>
                  <p className="text-xs bg-muted/30 rounded-lg p-3 whitespace-pre-wrap">{selected.resolutionNote}</p>
                </div>
              )}

              {/* Status update (admin action would expand this; client can see read-only) */}
              {selected.status !== "closed" && selected.status !== "rejected" && (
                <div className="pt-2 border-t border-border">
                  <p className="text-xs text-muted-foreground mb-2">Update Status</p>
                  <div className="flex gap-2">
                    {selected.status === "submitted" && (
                      <Button size="sm" variant="outline"
                        onClick={() => updateMutation.mutate({ id: selected.id, status: "in_progress" })}>
                        Mark In Progress
                      </Button>
                    )}
                    <Button size="sm" variant="outline" className="text-green-400 border-green-500/30 hover:bg-green-500/10"
                      onClick={() => updateMutation.mutate({ id: selected.id, status: "closed", isSuccessful: true })}>
                      Mark Closed
                    </Button>
                    <Button size="sm" variant="outline" className="text-red-400 border-red-500/30 hover:bg-red-500/10"
                      onClick={() => updateMutation.mutate({ id: selected.id, status: "rejected" })}>
                      Reject
                    </Button>
                  </div>
                </div>
              )}
            </div>
          </DialogContent>
        </Dialog>
      )}
    </div>
  );
}
