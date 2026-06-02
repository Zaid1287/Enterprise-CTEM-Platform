import { useState } from "react";

import {
  useListAssets, useCreateAsset, useDeleteAsset, useCheckAssetVerification,
  useListUsers,
  getListAssetsQueryKey,
} from "@workspace/api-client-react";
import { useQueryClient } from "@tanstack/react-query";
import { Plus, Search, Trash2, ExternalLink, RefreshCw, ShieldCheck } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { cn, statusBadgeClass, capitalize, formatDate, riskLevelBg } from "@/lib/utils";
import { Link } from "wouter";

const ASSET_TYPES = ["domain", "subdomain", "url", "ip", "cidr", "api", "ssl_cert", "cloud_asset", "host", "mobile_app"];

const emptyForm = {
  name: "", type: "domain", value: "", description: "",
  assignedClientId: undefined as number | undefined,
  assignedAccountManagerId: undefined as number | undefined,
};

export default function AssetsPage() {
  const [search, setSearch] = useState("");
  const [typeFilter, setTypeFilter] = useState("");
  const [showCreate, setShowCreate] = useState(false);
  const [newAsset, setNewAsset] = useState({ ...emptyForm });
  const [verifyingId, setVerifyingId] = useState<number | null>(null);
  const queryClient = useQueryClient();

  const params = { search: search || undefined, type: typeFilter || undefined };
  const { data: assets, isLoading } = useListAssets(params as any, {
    query: { queryKey: getListAssetsQueryKey(params as any) },
  });
  const { data: usersData } = useListUsers();
  const users = (usersData as any[]) ?? [];
  const clients = users.filter((u: any) => u.role === "client");
  const accountManagers = users.filter((u: any) => u.role === "account_manager");

  const createAsset = useCreateAsset();
  const deleteAsset = useDeleteAsset();
  const verifyAsset = useCheckAssetVerification();

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    const payload: any = {
      name: newAsset.name,
      type: newAsset.type,
      value: newAsset.value,
      description: newAsset.description || undefined,
    };
    if (newAsset.assignedClientId) payload.assignedClientId = newAsset.assignedClientId;
    if (newAsset.assignedAccountManagerId) payload.assignedAccountManagerId = newAsset.assignedAccountManagerId;
    await createAsset.mutateAsync({ data: payload } as any);
    queryClient.invalidateQueries({ queryKey: getListAssetsQueryKey() });
    setShowCreate(false);
    setNewAsset({ ...emptyForm });
  };

  const handleDelete = async (id: number) => {
    if (!confirm("Delete this asset?")) return;
    await deleteAsset.mutateAsync({ assetId: id });
    queryClient.invalidateQueries({ queryKey: getListAssetsQueryKey() });
  };

  const handleVerify = async (id: number) => {
    setVerifyingId(id);
    try {
      await verifyAsset.mutateAsync({ assetId: id });
      queryClient.invalidateQueries({ queryKey: getListAssetsQueryKey() });
    } finally {
      setVerifyingId(null);
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold">Asset Inventory</h1>
          <p className="text-sm text-muted-foreground">{Array.isArray(assets) ? assets.length : 0} assets tracked</p>
        </div>
        <Button size="sm" onClick={() => setShowCreate(true)}>
          <Plus className="w-4 h-4 mr-1.5" /> Add Asset
        </Button>
      </div>

      {/* Filters */}
      <div className="flex gap-2">
        <div className="relative flex-1 max-w-xs">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
          <Input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search assets..." className="pl-8 h-8 text-sm" />
        </div>
        <Select value={typeFilter || "_all_"} onValueChange={(v) => setTypeFilter(v === "_all_" ? "" : v)}>
          <SelectTrigger className="w-36 h-8 text-sm">
            <SelectValue placeholder="All types" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="_all_">All types</SelectItem>
            {ASSET_TYPES.map(t => <SelectItem key={t} value={t}>{capitalize(t)}</SelectItem>)}
          </SelectContent>
        </Select>
        <Button variant="outline" size="sm" onClick={() => { setSearch(""); setTypeFilter(""); }}>
          <RefreshCw className="w-3.5 h-3.5" />
        </Button>
      </div>

      {/* Table */}
      <div className="bg-card border border-border rounded-xl overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border">
              <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Name</th>
              <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Type</th>
              <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Value</th>
              <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Risk</th>
              <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Status</th>
              <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Client</th>
              <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Account Mgr</th>
              <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Last Scan</th>
              <th className="px-4 py-2.5" />
            </tr>
          </thead>
          <tbody>
            {isLoading && [...Array(5)].map((_, i) => (
              <tr key={i} className="border-b border-border/50">
                {[...Array(9)].map((_, j) => <td key={j} className="px-4 py-3"><Skeleton className="h-4" /></td>)}
              </tr>
            ))}
            {!isLoading && (assets as any[] ?? []).map((asset: any) => (
              <tr key={asset.id} className="border-b border-border/50 hover:bg-accent/30 transition-colors">
                <td className="px-4 py-2.5">
                  <Link href={`/assets/${asset.id}`}>
                    <span className="font-medium text-primary hover:underline cursor-pointer">{asset.name}</span>
                  </Link>
                </td>
                <td className="px-4 py-2.5">
                  <span className="text-xs text-muted-foreground bg-accent/50 px-2 py-0.5 rounded">{asset.type}</span>
                </td>
                <td className="px-4 py-2.5 text-muted-foreground text-xs font-mono">{asset.value}</td>
                <td className="px-4 py-2.5">
                  <span className={cn("text-xs px-2 py-0.5 rounded-md font-medium", riskLevelBg(asset.riskLevel))}>
                    {asset.riskLevel}
                  </span>
                </td>
                <td className="px-4 py-2.5">
                  <span className={cn("text-xs px-2 py-0.5 rounded-md font-medium", statusBadgeClass(asset.verificationStatus))}>
                    {asset.verificationStatus}
                  </span>
                </td>
                <td className="px-4 py-2.5 text-xs text-muted-foreground">{asset.assignedClientName ?? "—"}</td>
                <td className="px-4 py-2.5 text-xs text-muted-foreground">{asset.assignedAccountManagerName ?? "—"}</td>
                <td className="px-4 py-2.5 text-xs text-muted-foreground">{formatDate(asset.lastScannedAt)}</td>
                <td className="px-4 py-2.5">
                  <div className="flex items-center gap-1">
                    {asset.verificationStatus !== "verified" && (
                      <Button
                        variant="ghost"
                        size="sm"
                        className="h-7 px-2 text-xs text-green-500 hover:text-green-400 hover:bg-green-500/10"
                        disabled={verifyingId === asset.id}
                        onClick={() => handleVerify(asset.id)}
                      >
                        <ShieldCheck className="w-3.5 h-3.5 mr-1" />
                        {verifyingId === asset.id ? "…" : "Verify"}
                      </Button>
                    )}
                    <Link href={`/assets/${asset.id}`}>
                      <Button variant="ghost" size="icon" className="h-7 w-7">
                        <ExternalLink className="w-3.5 h-3.5" />
                      </Button>
                    </Link>
                    <Button variant="ghost" size="icon" className="h-7 w-7 text-destructive hover:text-destructive" onClick={() => handleDelete(asset.id)}>
                      <Trash2 className="w-3.5 h-3.5" />
                    </Button>
                  </div>
                </td>
              </tr>
            ))}
            {!isLoading && (assets as any[] ?? []).length === 0 && (
              <tr>
                <td colSpan={9} className="px-4 py-8 text-center text-sm text-muted-foreground">
                  No assets found. Add your first asset to get started.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Create Dialog */}
      <Dialog open={showCreate} onOpenChange={setShowCreate}>
        <DialogContent>
          <DialogHeader><DialogTitle>Add Asset</DialogTitle></DialogHeader>
          <form onSubmit={handleCreate} className="space-y-3 mt-2">
            <div className="space-y-1.5">
              <Label className="text-xs">Asset Name</Label>
              <Input value={newAsset.name} onChange={e => setNewAsset(p => ({ ...p, name: e.target.value }))} placeholder="Main Website" required className="h-9" />
            </div>
            <div className="space-y-1.5">
              <Label className="text-xs">Type</Label>
              <Select value={newAsset.type} onValueChange={v => setNewAsset(p => ({ ...p, type: v }))}>
                <SelectTrigger className="h-9"><SelectValue /></SelectTrigger>
                <SelectContent>
                  {ASSET_TYPES.map(t => <SelectItem key={t} value={t}>{capitalize(t)}</SelectItem>)}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1.5">
              <Label className="text-xs">Value (domain/IP/URL)</Label>
              <Input value={newAsset.value} onChange={e => setNewAsset(p => ({ ...p, value: e.target.value }))} placeholder="example.com" required className="h-9 font-mono text-sm" />
            </div>
            <div className="space-y-1.5">
              <Label className="text-xs">Description (optional)</Label>
              <Input value={newAsset.description} onChange={e => setNewAsset(p => ({ ...p, description: e.target.value }))} className="h-9" />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <Label className="text-xs">Assign Client</Label>
                <Select
                  value={newAsset.assignedClientId?.toString() ?? "_none_"}
                  onValueChange={v => setNewAsset(p => ({ ...p, assignedClientId: v === "_none_" ? undefined : parseInt(v) }))}
                >
                  <SelectTrigger className="h-9 text-xs"><SelectValue placeholder="None" /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="_none_">None</SelectItem>
                    {clients.map((u: any) => (
                      <SelectItem key={u.id} value={u.id.toString()}>{u.firstName} {u.lastName}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs">Account Manager</Label>
                <Select
                  value={newAsset.assignedAccountManagerId?.toString() ?? "_none_"}
                  onValueChange={v => setNewAsset(p => ({ ...p, assignedAccountManagerId: v === "_none_" ? undefined : parseInt(v) }))}
                >
                  <SelectTrigger className="h-9 text-xs"><SelectValue placeholder="None" /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="_none_">None</SelectItem>
                    {accountManagers.map((u: any) => (
                      <SelectItem key={u.id} value={u.id.toString()}>{u.firstName} {u.lastName}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>
            <DialogFooter className="mt-4">
              <Button variant="outline" type="button" onClick={() => setShowCreate(false)}>Cancel</Button>
              <Button type="submit" disabled={createAsset.isPending}>{createAsset.isPending ? "Creating..." : "Add Asset"}</Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </div>
  );
}
