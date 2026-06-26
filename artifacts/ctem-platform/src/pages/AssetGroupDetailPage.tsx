import { useState } from "react";
import { useLocation, useParams } from "wouter";
import {
  useGetAssetGroup, useUpdateAssetGroup, useGetAssetGroupMembers, useSetAssetGroupMembers,
  useListAssets, useCreateScan, getGetAssetGroupQueryKey, getGetAssetGroupMembersQueryKey, getListAssetGroupsQueryKey,
} from "@workspace/api-client-react";
import { useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, Layers, Save, Users, Plus, X, Globe, Server, Database, Code2, Wifi, Shield, FileText, Play, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import { cn, formatDate } from "@/lib/utils";
import { useToast } from "@/hooks/use-toast";

const ASSET_TYPE_ICON: Record<string, React.ElementType> = {
  domain: Globe, ip: Wifi, host: Server, cloud: Shield,
  api: Code2, database: Database, service: Server, other: FileText,
};

export default function AssetGroupDetailPage() {
  const [, navigate] = useLocation();
  const params = useParams<{ groupId: string }>();
  const groupId = Number(params.groupId);
  const qc = useQueryClient();

  const [editing, setEditing] = useState(false);
  const [form, setForm] = useState({ name: "", description: "" });
  const [saving, setSaving] = useState(false);
  const [assignOpen, setAssignOpen] = useState(false);
  const [selected, setSelected] = useState<number[]>([]);
  const [scanningGroup, setScanningGroup] = useState(false);
  const createScan = useCreateScan();
  const { toast } = useToast();

  const { data: group, isLoading } = useGetAssetGroup(groupId, {
    query: { queryKey: getGetAssetGroupQueryKey(groupId) },
  });
  const { data: members, isLoading: loadingMembers } = useGetAssetGroupMembers(groupId, {
    query: { queryKey: getGetAssetGroupMembersQueryKey(groupId) },
  });
  const { data: allAssets } = useListAssets({} as any);
  const updateGroup = useUpdateAssetGroup();
  const setMembers = useSetAssetGroupMembers();

  const g = group as any;
  const memberList = (members as any[]) ?? [];
  const allAssetList = (allAssets as any[]) ?? [];

  function startEdit() {
    setForm({ name: g?.name ?? "", description: g?.description ?? "" });
    setEditing(true);
  }

  async function saveEdit() {
    setSaving(true);
    await updateGroup.mutateAsync({ groupId, data: form });
    qc.invalidateQueries({ queryKey: getGetAssetGroupQueryKey(groupId) });
    qc.invalidateQueries({ queryKey: getListAssetGroupsQueryKey() });
    setSaving(false);
    setEditing(false);
  }

  function openAssign() {
    setSelected(memberList.map((m: any) => m.id));
    setAssignOpen(true);
  }

  async function saveMembers() {
    await setMembers.mutateAsync({ groupId, data: { assetIds: selected } });
    qc.invalidateQueries({ queryKey: getGetAssetGroupMembersQueryKey(groupId) });
    qc.invalidateQueries({ queryKey: getGetAssetGroupQueryKey(groupId) });
    qc.invalidateQueries({ queryKey: getListAssetGroupsQueryKey() });
    setAssignOpen(false);
  }

  function toggleAsset(id: number) {
    setSelected(prev => prev.includes(id) ? prev.filter(x => x !== id) : [...prev, id]);
  }

  if (isLoading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-8 w-48" />
        <Skeleton className="h-28 rounded-xl" />
        <Skeleton className="h-64 rounded-xl" />
      </div>
    );
  }

  return (
    <div className="space-y-5 max-w-3xl">
      {/* Back */}
      <Button variant="ghost" size="sm" className="gap-1.5 -ml-2 text-muted-foreground" onClick={() => navigate("/asset-groups")}>
        <ArrowLeft className="w-4 h-4" /> Asset Groups
      </Button>

      {/* Header card */}
      <div className="bg-card border border-border rounded-xl p-5">
        <div className="flex items-start justify-between mb-4">
          <div className="flex items-center gap-2">
            <div className="w-8 h-8 rounded-lg bg-primary/10 border border-primary/20 flex items-center justify-center">
              <Layers className="w-4 h-4 text-primary" />
            </div>
            {editing ? (
              <div className="space-y-1">
                <Input value={form.name} onChange={e => setForm(p => ({ ...p, name: e.target.value }))} className="h-8 text-sm font-medium" />
                <Input value={form.description} onChange={e => setForm(p => ({ ...p, description: e.target.value }))} placeholder="Description (optional)" className="h-7 text-xs" />
              </div>
            ) : (
              <div>
                <h1 className="text-base font-semibold">{g?.name}</h1>
                {g?.description && <p className="text-xs text-muted-foreground">{g.description}</p>}
              </div>
            )}
          </div>
          {editing ? (
            <div className="flex gap-1.5">
              <Button variant="outline" size="sm" className="h-7 text-xs" onClick={() => setEditing(false)}>Cancel</Button>
              <Button size="sm" className="h-7 text-xs gap-1" onClick={saveEdit} disabled={saving}>
                <Save className="w-3 h-3" />{saving ? "Saving…" : "Save"}
              </Button>
            </div>
          ) : (
            <div className="flex gap-1.5">
              <Button
                variant="outline" size="sm" className="h-7 text-xs gap-1"
                disabled={scanningGroup || memberList.length === 0}
                onClick={async () => {
                  const ids = memberList.filter((a: any) => a.verificationStatus === "verified").map((a: any) => a.id);
                  if (ids.length === 0) {
                    toast({ title: "No verified assets", description: "Verify ownership of at least one asset before scanning.", variant: "destructive" });
                    return;
                  }
                  setScanningGroup(true);
                  try {
                    await createScan.mutateAsync({ data: { type: "full", assetIds: ids } } as any);
                    toast({ title: "Scan started", description: `Scanning ${ids.length} asset(s) in this group.` });
                    navigate("/scans");
                  } catch {
                    toast({ title: "Failed to start scan", variant: "destructive" });
                  } finally {
                    setScanningGroup(false);
                  }
                }}
              >
                {scanningGroup ? <Loader2 className="w-3 h-3 animate-spin" /> : <Play className="w-3 h-3" />}
                {scanningGroup ? "Starting…" : "Scan Group"}
              </Button>
              <Button variant="outline" size="sm" className="h-7 text-xs" onClick={startEdit}>Edit</Button>
            </div>
          )}
        </div>
        <div className="flex gap-4 text-xs text-muted-foreground">
          <span>{memberList.length} assets</span>
          {g?.createdAt && <span>Created {formatDate(g.createdAt)}</span>}
        </div>
      </div>

      {/* Members panel */}
      <div>
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-sm font-medium flex items-center gap-1.5">
            <Users className="w-4 h-4 text-muted-foreground" /> Members
          </h2>
          <Button size="sm" variant="outline" className="h-7 text-xs gap-1" onClick={openAssign}>
            <Plus className="w-3 h-3" /> Assign Assets
          </Button>
        </div>

        <div className="bg-card border border-border rounded-xl overflow-hidden">
          {loadingMembers && (
            <div className="p-4 space-y-2">
              {[...Array(4)].map((_, i) => <Skeleton key={i} className="h-10 rounded-lg" />)}
            </div>
          )}
          {!loadingMembers && memberList.length === 0 && (
            <div className="p-8 text-center text-sm text-muted-foreground">
              No assets assigned to this group yet.
            </div>
          )}
          {!loadingMembers && memberList.length > 0 && (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border">
                  <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Asset</th>
                  <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Type</th>
                  <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Value</th>
                  <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Risk</th>
                </tr>
              </thead>
              <tbody>
                {memberList.map((a: any) => {
                  const Icon = ASSET_TYPE_ICON[a.type] ?? FileText;
                  return (
                    <tr key={a.id} className="border-b border-border/50 hover:bg-accent/20">
                      <td className="px-4 py-2.5">
                        <div className="flex items-center gap-1.5">
                          <Icon className="w-3.5 h-3.5 text-muted-foreground shrink-0" />
                          <span className="font-medium text-xs">{a.name}</span>
                        </div>
                      </td>
                      <td className="px-4 py-2.5 text-xs text-muted-foreground capitalize">{a.type}</td>
                      <td className="px-4 py-2.5 text-xs font-mono text-primary/80 truncate max-w-[160px]">{a.value}</td>
                      <td className="px-4 py-2.5">
                        {a.riskScore != null && (
                          <span className={cn(
                            "text-[10px] px-1.5 py-0.5 rounded font-bold",
                            a.riskScore >= 80 ? "bg-red-500/15 text-red-400" :
                            a.riskScore >= 60 ? "bg-orange-500/15 text-orange-400" :
                            a.riskScore >= 40 ? "bg-yellow-500/15 text-yellow-400" :
                            "bg-green-500/15 text-green-400"
                          )}>{a.riskScore}</span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {/* Assign Assets modal */}
      {assignOpen && (
        <div className="fixed inset-0 z-50 bg-black/60 flex items-center justify-center p-4">
          <div className="bg-card border border-border rounded-xl w-full max-w-md shadow-2xl">
            <div className="flex items-center justify-between px-5 py-4 border-b border-border">
              <h3 className="text-sm font-semibold">Assign Assets to Group</h3>
              <Button variant="ghost" size="icon" className="h-7 w-7" onClick={() => setAssignOpen(false)}>
                <X className="w-4 h-4" />
              </Button>
            </div>
            <div className="p-4">
              <p className="text-xs text-muted-foreground mb-3">{selected.length} of {allAssetList.length} selected</p>
              <div className="border border-border rounded-lg max-h-64 overflow-y-auto">
                {allAssetList.map((a: any) => {
                  const Icon = ASSET_TYPE_ICON[a.type] ?? FileText;
                  return (
                    <label key={a.id} className="flex items-center gap-2 px-3 py-2.5 hover:bg-accent/30 cursor-pointer border-b border-border/50 last:border-0">
                      <input
                        type="checkbox"
                        checked={selected.includes(a.id)}
                        onChange={() => toggleAsset(a.id)}
                        className="accent-primary"
                      />
                      <Icon className="w-3.5 h-3.5 text-muted-foreground shrink-0" />
                      <span className="text-sm flex-1">{a.name}</span>
                      <span className="text-xs text-muted-foreground">{a.type}</span>
                    </label>
                  );
                })}
              </div>
            </div>
            <div className="flex justify-end gap-2 px-5 py-3 border-t border-border">
              <Button variant="outline" size="sm" onClick={() => setAssignOpen(false)}>Cancel</Button>
              <Button size="sm" onClick={saveMembers} disabled={setMembers.isPending}>
                {setMembers.isPending ? "Saving…" : "Save Members"}
              </Button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
