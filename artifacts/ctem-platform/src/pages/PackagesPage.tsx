import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Plus, Pencil, Trash2, Package, DollarSign, Users, Server } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog";
import { Skeleton } from "@/components/ui/skeleton";
import { Badge } from "@/components/ui/badge";
import { apiFetch } from "@/lib/apiFetch";
import { useToast } from "@/hooks/use-toast";
import { cn } from "@/lib/utils";

interface PkgData {
  id: number;
  name: string;
  description: string | null;
  price: number;
  features: string[];
  maxAssets: number | null;
  maxUsers: number | null;
  isActive: boolean;
  createdAt: string;
}

const BASE = import.meta.env.BASE_URL.replace(/\/$/, "");

const emptyForm = { name: "", description: "", price: "0", features: "", maxAssets: "", maxUsers: "" };

export default function PackagesPage() {
  const [showCreate, setShowCreate] = useState(false);
  const [editPkg, setEditPkg] = useState<PkgData | null>(null);
  const [form, setForm] = useState(emptyForm);
  const queryClient = useQueryClient();
  const { toast } = useToast();

  const { data: packages = [], isLoading } = useQuery<PkgData[]>({
    queryKey: ["packages"],
    queryFn: () => apiFetch(`${BASE}/api/packages`),
  });

  const createMutation = useMutation({
    mutationFn: (body: object) => apiFetch(`${BASE}/api/packages`, { method: "POST", body: JSON.stringify(body) }),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ["packages"] }); setShowCreate(false); setForm(emptyForm); toast({ title: "Package created" }); },
    onError: (e: any) => toast({ title: "Error", description: e.message, variant: "destructive" }),
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, ...body }: { id: number } & object) => apiFetch(`${BASE}/api/packages/${id}`, { method: "PATCH", body: JSON.stringify(body) }),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ["packages"] }); setEditPkg(null); toast({ title: "Package updated" }); },
    onError: (e: any) => toast({ title: "Error", description: e.message, variant: "destructive" }),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: number) => apiFetch(`${BASE}/api/packages/${id}`, { method: "DELETE" }),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ["packages"] }); toast({ title: "Package deleted" }); },
    onError: (e: any) => toast({ title: "Error", description: e.message, variant: "destructive" }),
  });

  function parseForm(f: typeof emptyForm) {
    return {
      name: f.name,
      description: f.description || null,
      price: parseFloat(f.price) || 0,
      features: f.features.split("\n").map(s => s.trim()).filter(Boolean),
      maxAssets: f.maxAssets ? parseInt(f.maxAssets) : null,
      maxUsers: f.maxUsers ? parseInt(f.maxUsers) : null,
    };
  }

  function openEdit(pkg: PkgData) {
    setEditPkg(pkg);
    setForm({
      name: pkg.name,
      description: pkg.description ?? "",
      price: String(pkg.price),
      features: pkg.features.join("\n"),
      maxAssets: pkg.maxAssets != null ? String(pkg.maxAssets) : "",
      maxUsers: pkg.maxUsers != null ? String(pkg.maxUsers) : "",
    });
  }

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold">Package Management</h1>
          <p className="text-sm text-muted-foreground">Define and manage service packages for client tenants</p>
        </div>
        <Button size="sm" onClick={() => { setForm(emptyForm); setShowCreate(true); }}>
          <Plus className="w-4 h-4 mr-1.5" /> New Package
        </Button>
      </div>

      {isLoading ? (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {[...Array(3)].map((_, i) => <Skeleton key={i} className="h-48 rounded-xl" />)}
        </div>
      ) : packages.length === 0 ? (
        <div className="flex flex-col items-center justify-center h-48 text-muted-foreground">
          <Package className="w-10 h-10 mb-2 opacity-30" />
          <p className="text-sm">No packages yet. Create your first one.</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {packages.map(pkg => (
            <div key={pkg.id} className={cn("bg-card border border-border rounded-xl p-5 flex flex-col gap-3", !pkg.isActive && "opacity-60")}>
              <div className="flex items-start justify-between">
                <div>
                  <h3 className="font-semibold">{pkg.name}</h3>
                  {pkg.description && <p className="text-xs text-muted-foreground mt-0.5">{pkg.description}</p>}
                </div>
                <Badge variant={pkg.isActive ? "default" : "secondary"} className="text-xs">
                  {pkg.isActive ? "Active" : "Inactive"}
                </Badge>
              </div>

              <div className="flex items-center gap-1.5 text-lg font-bold text-primary">
                <DollarSign className="w-4 h-4" />
                {pkg.price.toFixed(2)}<span className="text-xs text-muted-foreground font-normal ml-0.5">/mo</span>
              </div>

              <div className="flex gap-3 text-xs text-muted-foreground">
                {pkg.maxAssets != null && (
                  <span className="flex items-center gap-1"><Server className="w-3 h-3" />{pkg.maxAssets} assets</span>
                )}
                {pkg.maxUsers != null && (
                  <span className="flex items-center gap-1"><Users className="w-3 h-3" />{pkg.maxUsers} users</span>
                )}
              </div>

              {pkg.features.length > 0 && (
                <ul className="text-xs text-muted-foreground space-y-0.5">
                  {pkg.features.slice(0, 4).map((f, i) => <li key={i} className="flex items-center gap-1.5">✓ {f}</li>)}
                  {pkg.features.length > 4 && <li className="text-muted-foreground/60">+{pkg.features.length - 4} more</li>}
                </ul>
              )}

              <div className="flex gap-2 mt-auto pt-2 border-t border-border">
                <Button variant="outline" size="sm" className="flex-1" onClick={() => openEdit(pkg)}>
                  <Pencil className="w-3.5 h-3.5 mr-1" /> Edit
                </Button>
                <Button variant="ghost" size="icon" className="h-8 w-8 text-destructive hover:text-destructive"
                  onClick={() => confirm("Delete this package?") && deleteMutation.mutate(pkg.id)}>
                  <Trash2 className="w-3.5 h-3.5" />
                </Button>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Create / Edit Dialog */}
      <Dialog open={showCreate || !!editPkg} onOpenChange={v => { if (!v) { setShowCreate(false); setEditPkg(null); } }}>
        <DialogContent>
          <DialogHeader><DialogTitle>{editPkg ? "Edit Package" : "New Package"}</DialogTitle></DialogHeader>
          <form className="space-y-3 mt-2" onSubmit={e => {
            e.preventDefault();
            const data = parseForm(form);
            if (editPkg) updateMutation.mutate({ id: editPkg.id, ...data });
            else createMutation.mutate(data);
          }}>
            <div className="space-y-1.5">
              <Label className="text-xs">Name</Label>
              <Input value={form.name} onChange={e => setForm(p => ({ ...p, name: e.target.value }))} required className="h-9" placeholder="Starter / Professional / Enterprise" />
            </div>
            <div className="space-y-1.5">
              <Label className="text-xs">Description</Label>
              <Input value={form.description} onChange={e => setForm(p => ({ ...p, description: e.target.value }))} className="h-9" />
            </div>
            <div className="grid grid-cols-3 gap-2">
              <div className="space-y-1.5">
                <Label className="text-xs">Price ($/mo)</Label>
                <Input type="number" value={form.price} onChange={e => setForm(p => ({ ...p, price: e.target.value }))} min="0" step="0.01" className="h-9" />
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs">Max Assets</Label>
                <Input type="number" value={form.maxAssets} onChange={e => setForm(p => ({ ...p, maxAssets: e.target.value }))} min="1" className="h-9" placeholder="unlimited" />
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs">Max Users</Label>
                <Input type="number" value={form.maxUsers} onChange={e => setForm(p => ({ ...p, maxUsers: e.target.value }))} min="1" className="h-9" placeholder="unlimited" />
              </div>
            </div>
            <div className="space-y-1.5">
              <Label className="text-xs">Features (one per line)</Label>
              <Textarea value={form.features} onChange={e => setForm(p => ({ ...p, features: e.target.value }))} rows={4} placeholder={"Asset Discovery\nVulnerability Scanning\nCompliance Tracking"} className="text-xs" />
            </div>
            <DialogFooter className="mt-4">
              <Button variant="outline" type="button" onClick={() => { setShowCreate(false); setEditPkg(null); }}>Cancel</Button>
              <Button type="submit" disabled={createMutation.isPending || updateMutation.isPending}>
                {createMutation.isPending || updateMutation.isPending ? "Saving..." : editPkg ? "Update" : "Create"}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </div>
  );
}
