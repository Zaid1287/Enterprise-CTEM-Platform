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
import { cn, formatDate } from "@/lib/utils";

export const GROUP_COLORS = [
  { id: "slate",  bg: "bg-slate-500",  ring: "border-l-slate-500"  },
  { id: "blue",   bg: "bg-blue-500",   ring: "border-l-blue-500"   },
  { id: "violet", bg: "bg-violet-500", ring: "border-l-violet-500" },
  { id: "green",  bg: "bg-green-500",  ring: "border-l-green-500"  },
  { id: "amber",  bg: "bg-amber-500",  ring: "border-l-amber-500"  },
  { id: "red",    bg: "bg-red-500",    ring: "border-l-red-500"    },
  { id: "pink",   bg: "bg-pink-500",   ring: "border-l-pink-500"   },
  { id: "teal",   bg: "bg-teal-500",   ring: "border-l-teal-500"   },
];

export function getGroupColor(id: string) {
  return GROUP_COLORS.find(c => c.id === id) ?? GROUP_COLORS[0];
}

export default function AssetGroupsPage() {
  const [, navigate] = useLocation();
  const [showCreate, setShowCreate] = useState(false);
  const [form, setForm] = useState({ name: "", description: "", color: "slate", assetIds: [] as number[] });
  const [assetSearch, setAssetSearch] = useState("");
  const queryClient = useQueryClient();

  const { data: groups, isLoading } = useListAssetGroups({
    query: { queryKey: getListAssetGroupsQueryKey() },
  });
  const { data: assets } = useListAssets({} as any, {
    query: { queryKey: getListAssetsQueryKey({} as any) },
  });
  const createGroup = useCreateAssetGroup();
  const deleteGroup = useDeleteAssetGroup();

  const assetList = (assets as any[]) ?? [];
  const filteredAssets = assetSearch
    ? assetList.filter((a: any) =>
        (a.name ?? "").toLowerCase().includes(assetSearch.toLowerCase()) ||
        (a.value ?? "").toLowerCase().includes(assetSearch.toLowerCase()))
    : assetList;

  function handleClose() { setShowCreate(false); setAssetSearch(""); setForm({ name: "", description: "", color: "slate", assetIds: [] }); }

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    await createGroup.mutateAsync({ data: form } as any);
    queryClient.invalidateQueries({ queryKey: getListAssetGroupsQueryKey() });
    handleClose();
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
          <p className="text-sm text-muted-foreground">Organize assets into logical groups for scans, alerts, and compliance</p>
        </div>
        <Button size="sm" onClick={() => setShowCreate(true)}>
          <Plus className="w-4 h-4 mr-1.5" /> New Group
        </Button>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
        {isLoading && [...Array(4)].map((_, i) => <Skeleton key={i} className="h-28 rounded-xl" />)}
        {!isLoading && (groups as any[] ?? []).map((g: any) => {
          const color = getGroupColor(g.color ?? "slate");
          return (
            <div
              key={g.id}
              className={cn(
                "bg-card border border-border border-l-4 rounded-xl p-4 hover:border-primary/40 transition-colors cursor-pointer group",
                color.ring,
              )}
              onClick={() => navigate(`/asset-groups/${g.id}`)}
            >
              <div className="flex items-start justify-between mb-2">
                <div className="flex items-center gap-2">
                  <div className={cn("w-2.5 h-2.5 rounded-full shrink-0", color.bg)} />
                  <p className="text-sm font-medium">{g.name}</p>
                </div>
                <div className="flex items-center gap-0.5">
                  <Button
                    variant="ghost" size="icon" className="h-7 w-7 text-destructive hover:text-destructive"
                    onClick={async (e) => {
                      e.stopPropagation();
                      if (confirm("Delete group? The assets themselves won't be removed.")) {
                        await deleteGroup.mutateAsync({ groupId: g.id });
                        queryClient.invalidateQueries({ queryKey: getListAssetGroupsQueryKey() });
                      }
                    }}
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </Button>
                  <ChevronRight className="w-4 h-4 text-muted-foreground/50 group-hover:text-muted-foreground transition-colors" />
                </div>
              </div>
              {g.description && <p className="text-xs text-muted-foreground mb-2 line-clamp-1">{g.description}</p>}
              <div className="flex items-center justify-between mt-3 gap-2">
                <span className="text-xs text-muted-foreground">{g.assetCount} asset{g.assetCount !== 1 ? "s" : ""}</span>
                <div className="flex items-center gap-1.5">
                  {g.avgRisk != null && (
                    <span className={cn(
                      "text-[10px] px-1.5 py-0.5 rounded font-bold",
                      g.worstLevel === "critical" ? "bg-red-500/15 text-red-400" :
                      g.worstLevel === "high"     ? "bg-orange-500/15 text-orange-400" :
                      g.worstLevel === "medium"   ? "bg-yellow-500/15 text-yellow-400" :
                      "bg-green-500/15 text-green-400"
                    )}>Risk {g.avgRisk}</span>
                  )}
                  <span className="text-[10px] text-muted-foreground">{formatDate(g.createdAt)}</span>
                </div>
              </div>
            </div>
          );
        })}
        {!isLoading && (groups as any[] ?? []).length === 0 && (
          <div className="col-span-3 bg-card border border-border rounded-xl p-8 text-center">
            <Layers className="w-8 h-8 text-muted-foreground/30 mx-auto mb-2" />
            <p className="text-sm text-muted-foreground">No asset groups yet. Create one to organize your assets.</p>
          </div>
        )}
      </div>

      {/* Create dialog */}
      <Dialog open={showCreate} onOpenChange={o => { if (!o) handleClose(); }}>
        <DialogContent className="max-w-lg">
          <DialogHeader><DialogTitle>Create Asset Group</DialogTitle></DialogHeader>
          <form onSubmit={handleCreate} className="space-y-4 mt-1">

            <div className="space-y-1.5">
              <Label className="text-xs">Group Name</Label>
              <Input value={form.name} onChange={e => setForm(p => ({ ...p, name: e.target.value }))} placeholder="Production Assets" required className="h-9" />
            </div>

            <div className="space-y-1.5">
              <Label className="text-xs">Description (optional)</Label>
              <Input value={form.description} onChange={e => setForm(p => ({ ...p, description: e.target.value }))} className="h-9" />
            </div>

            {/* Color picker */}
            <div className="space-y-1.5">
              <Label className="text-xs">Color</Label>
              <div className="flex gap-2 flex-wrap">
                {GROUP_COLORS.map(c => (
                  <button
                    key={c.id}
                    type="button"
                    onClick={() => setForm(p => ({ ...p, color: c.id }))}
                    className={cn(
                      "w-6 h-6 rounded-full border-2 transition-all",
                      c.bg,
                      form.color === c.id ? "border-foreground scale-110" : "border-transparent opacity-60 hover:opacity-100"
                    )}
                    title={c.id}
                  />
                ))}
              </div>
            </div>

            {/* Asset picker */}
            <div className="space-y-1.5">
              <Label className="text-xs">Add Assets ({form.assetIds.length} selected)</Label>
              <Input
                value={assetSearch}
                onChange={e => setAssetSearch(e.target.value)}
                placeholder="Search assets by name or value…"
                className="h-8 text-xs"
              />
              <div className="border border-border rounded-lg max-h-44 overflow-y-auto">
                {filteredAssets.length === 0 && (
                  <p className="px-3 py-4 text-center text-xs text-muted-foreground">No assets found</p>
                )}
                {filteredAssets.map((a: any) => {
                  const isVerified = a.verificationStatus === "verified";
                  return (
                    <label
                      key={a.id}
                      className={cn(
                        "flex items-center gap-2 px-3 py-2 border-b border-border/40 last:border-0",
                        isVerified ? "cursor-pointer hover:bg-accent/30" : "opacity-50 cursor-not-allowed"
                      )}
                    >
                      <input
                        type="checkbox"
                        checked={form.assetIds.includes(a.id)}
                        onChange={() => isVerified && toggleAsset(a.id)}
                        disabled={!isVerified}
                        className="accent-primary shrink-0"
                      />
                      <span className="text-sm flex-1 truncate">{a.name}</span>
                      <span className="text-xs text-muted-foreground shrink-0">{a.type}</span>
                      {!isVerified && (
                        <span className="text-[9px] px-1 py-0.5 rounded bg-amber-500/15 text-amber-400 font-medium shrink-0">Unverified</span>
                      )}
                    </label>
                  );
                })}
              </div>
            </div>

            <DialogFooter>
              <Button variant="outline" type="button" onClick={handleClose}>Cancel</Button>
              <Button type="submit" disabled={createGroup.isPending}>{createGroup.isPending ? "Creating…" : "Create Group"}</Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </div>
  );
}
