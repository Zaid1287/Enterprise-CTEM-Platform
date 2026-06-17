import { useState } from "react";
import { useLocation } from "wouter";
import {
  useListAssetGroups, useCreateAssetGroup, useDeleteAssetGroup,
  useListAssets, getListAssetGroupsQueryKey, getListAssetsQueryKey,
} from "@workspace/api-client-react";
import { useQueryClient } from "@tanstack/react-query";
import { Plus, Trash2, Layers, ChevronRight } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog";
import { Skeleton } from "@/components/ui/skeleton";
import { formatDate } from "@/lib/utils";

export default function AssetGroupsPage() {
  const [, navigate] = useLocation();
  const [showCreate, setShowCreate] = useState(false);
  const [form, setForm] = useState({ name: "", description: "", assetIds: [] as number[] });
  const queryClient = useQueryClient();

  const { data: groups, isLoading } = useListAssetGroups({
    query: { queryKey: getListAssetGroupsQueryKey() },
  });
  const { data: assets } = useListAssets({} as any, {
    query: { queryKey: getListAssetsQueryKey({} as any) },
  });
  const createGroup = useCreateAssetGroup();
  const deleteGroup = useDeleteAssetGroup();

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    await createGroup.mutateAsync({ data: form } as any);
    queryClient.invalidateQueries({ queryKey: getListAssetGroupsQueryKey() });
    setShowCreate(false);
    setForm({ name: "", description: "", assetIds: [] });
  };

  const toggleAsset = (id: number) => setForm(prev => ({
    ...prev,
    assetIds: prev.assetIds.includes(id) ? prev.assetIds.filter(a => a !== id) : [...prev.assetIds, id],
  }));

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold">Asset Groups</h1>
          <p className="text-sm text-muted-foreground">Organize assets into logical groups</p>
        </div>
        <Button size="sm" onClick={() => setShowCreate(true)}>
          <Plus className="w-4 h-4 mr-1.5" /> New Group
        </Button>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
        {isLoading && [...Array(4)].map((_, i) => <Skeleton key={i} className="h-28 rounded-xl" />)}
        {!isLoading && (groups as any[] ?? []).map((g: any) => (
          <div
            key={g.id}
            className="bg-card border border-border rounded-xl p-4 hover:border-primary/40 transition-colors cursor-pointer group"
            onClick={() => navigate(`/asset-groups/${g.id}`)}
          >
            <div className="flex items-start justify-between mb-2">
              <div className="flex items-center gap-2">
                <Layers className="w-4 h-4 text-primary" />
                <p className="text-sm font-medium">{g.name}</p>
              </div>
              <div className="flex items-center gap-0.5">
                <Button variant="ghost" size="icon" className="h-7 w-7 text-destructive hover:text-destructive" onClick={async (e) => { e.stopPropagation(); if(confirm("Delete group?")) { await deleteGroup.mutateAsync({ groupId: g.id }); queryClient.invalidateQueries({ queryKey: getListAssetGroupsQueryKey() }); } }}>
                  <Trash2 className="w-3.5 h-3.5" />
                </Button>
                <ChevronRight className="w-4 h-4 text-muted-foreground/50 group-hover:text-muted-foreground transition-colors" />
              </div>
            </div>
            {g.description && <p className="text-xs text-muted-foreground mb-2">{g.description}</p>}
            <div className="flex items-center justify-between mt-3">
              <span className="text-xs text-muted-foreground">{g.assetCount} assets</span>
              <span className="text-xs text-muted-foreground">Created {formatDate(g.createdAt)}</span>
            </div>
          </div>
        ))}
        {!isLoading && (groups as any[] ?? []).length === 0 && (
          <div className="col-span-3 bg-card border border-border rounded-xl p-8 text-center text-sm text-muted-foreground">
            No asset groups yet.
          </div>
        )}
      </div>

      <Dialog open={showCreate} onOpenChange={setShowCreate}>
        <DialogContent>
          <DialogHeader><DialogTitle>Create Asset Group</DialogTitle></DialogHeader>
          <form onSubmit={handleCreate} className="space-y-3 mt-2">
            <div className="space-y-1.5">
              <Label className="text-xs">Group Name</Label>
              <Input value={form.name} onChange={e => setForm(p => ({ ...p, name: e.target.value }))} placeholder="Production Assets" required className="h-9" />
            </div>
            <div className="space-y-1.5">
              <Label className="text-xs">Description (optional)</Label>
              <Input value={form.description} onChange={e => setForm(p => ({ ...p, description: e.target.value }))} className="h-9" />
            </div>
            <div className="space-y-1.5">
              <Label className="text-xs">Assets ({form.assetIds.length} selected)</Label>
              <div className="border border-border rounded-lg max-h-40 overflow-y-auto">
                {(assets as any[] ?? []).map((a: any) => (
                  <label key={a.id} className="flex items-center gap-2 px-3 py-2 hover:bg-accent/30 cursor-pointer">
                    <input type="checkbox" checked={form.assetIds.includes(a.id)} onChange={() => toggleAsset(a.id)} />
                    <span className="text-sm">{a.name}</span>
                    <span className="text-xs text-muted-foreground ml-auto">{a.type}</span>
                  </label>
                ))}
              </div>
            </div>
            <DialogFooter className="mt-4">
              <Button variant="outline" type="button" onClick={() => setShowCreate(false)}>Cancel</Button>
              <Button type="submit" disabled={createGroup.isPending}>{createGroup.isPending ? "Creating..." : "Create Group"}</Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </div>
  );
}
