import { useEffect, useState } from "react";
import { Link } from "wouter";
import { apiFetch } from "@/lib/apiFetch";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { RefreshCw, CheckCircle2, AlertTriangle, XCircle, Clock, ChevronRight } from "lucide-react";

const DOC_TYPES = ["SOC2 Type II", "ISO 27001", "PCI DSS", "HIPAA BAA", "GDPR DPA", "ISO 27017"];

interface VendorComplianceRow {
  id: number;
  companyName: string;
  domain: string;
  logoUrl: string | null;
  docsByType: Record<string, { status: string; expiresAt: string | null; daysRemaining: number | null } | null>;
}

function cellIcon(doc: { status: string; daysRemaining: number | null } | null) {
  if (!doc) return <XCircle className="w-4 h-4 text-red-400 mx-auto" aria-label="Missing" />;
  if (doc.status === "expired" || (doc.daysRemaining !== null && doc.daysRemaining < 0)) return <AlertTriangle className="w-4 h-4 text-red-400 mx-auto" aria-label="Expired" />;
  if (doc.daysRemaining !== null && doc.daysRemaining <= 30) return <Clock className="w-4 h-4 text-yellow-400 mx-auto" aria-label={`Expiring in ${doc.daysRemaining}d`} />;
  return <CheckCircle2 className="w-4 h-4 text-green-400 mx-auto" aria-label="Valid" />;
}

export default function TprmCompliancePage() {
  const [rows, setRows]           = useState<VendorComplianceRow[]>([]);
  const [expiring, setExpiring]   = useState<any[]>([]);
  const [loading, setLoading]     = useState(true);

  const load = async () => {
    setLoading(true);
    try {
      const [vendors, exp] = await Promise.all([
        apiFetch<any>("/api/tprm/vendors?limit=200"),
        apiFetch<any[]>("/api/tprm/compliance/expiring"),
      ]);
      setExpiring(exp);

      // For each vendor fetch compliance docs (compact via vendor list + inline fetch)
      const vendorRows: VendorComplianceRow[] = [];
      await Promise.all((vendors.vendors ?? []).map(async (v: any) => {
        try {
          const comp = await apiFetch<any>(`/api/tprm/vendors/${v.id}/compliance`);
          const docsByType: Record<string, any> = {};
          for (const dt of DOC_TYPES) {
            const d = (comp.documents ?? []).find((x: any) => x.documentType === dt && x.status !== "expired");
            if (d) {
              const days = d.expiresAt ? Math.ceil((new Date(d.expiresAt).getTime() - Date.now()) / 86400000) : null;
              docsByType[dt] = { status: d.status, expiresAt: d.expiresAt, daysRemaining: days };
            } else {
              const expired = (comp.documents ?? []).find((x: any) => x.documentType === dt);
              docsByType[dt] = expired ? { status: "expired", expiresAt: expired.expiresAt, daysRemaining: -1 } : null;
            }
          }
          vendorRows.push({ id: v.id, companyName: v.companyName, domain: v.domain, logoUrl: v.logoUrl, docsByType });
        } catch { /* skip */ }
      }));
      setRows(vendorRows);
    } catch { /* ignore */ }
    setLoading(false);
  };

  useEffect(() => { load(); }, []);

  return (
    <div className="p-6 space-y-5 max-w-[1400px] mx-auto">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold">Compliance Coverage</h1>
          <p className="text-muted-foreground text-sm">Cross-vendor compliance document status board</p>
        </div>
        <Button variant="outline" size="sm" onClick={load}><RefreshCw className="w-4 h-4" /></Button>
      </div>

      {/* Expiring soon banner */}
      {expiring.length > 0 && (
        <Card className="bg-yellow-500/10 border-yellow-500/30">
          <CardContent className="py-3">
            <div className="flex items-start gap-2">
              <Clock className="w-4 h-4 text-yellow-400 mt-0.5 shrink-0" />
              <div>
                <p className="text-sm font-medium text-yellow-400">Compliance Documents Expiring Soon</p>
                <div className="flex flex-wrap gap-1.5 mt-1.5">
                  {expiring.map(d => (
                    <Link key={d.id} href={`/tprm/vendors/${d.vendorId}`}>
                      <Badge variant="outline" className="text-[10px] border-yellow-500/40 cursor-pointer hover:bg-yellow-500/10">
                        {d.documentType} – {d.daysRemaining}d
                      </Badge>
                    </Link>
                  ))}
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Matrix table */}
      {loading ? (
        <Skeleton className="h-64" />
      ) : rows.length === 0 ? (
        <Card className="border-dashed">
          <CardContent className="py-14 text-center text-sm text-muted-foreground">
            No vendors yet. <Link href="/tprm/vendors" className="text-primary underline">Add vendors</Link> to track their compliance documents.
          </CardContent>
        </Card>
      ) : (
        <Card>
          <CardContent className="p-0 overflow-x-auto">
            <table className="w-full text-sm border-collapse">
              <thead>
                <tr className="border-b border-border/50">
                  <th className="text-left text-xs text-muted-foreground font-medium px-4 py-2.5 sticky left-0 bg-card z-10 min-w-[200px]">Vendor</th>
                  {DOC_TYPES.map(dt => (
                    <th key={dt} className="text-center text-xs text-muted-foreground font-medium px-3 py-2.5 whitespace-nowrap">{dt}</th>
                  ))}
                  <th className="px-4 py-2.5 w-10" />
                </tr>
              </thead>
              <tbody>
                {rows.map(r => (
                  <tr key={r.id} className="border-b border-border/30 hover:bg-accent/20 transition-colors">
                    <td className="px-4 py-3 sticky left-0 bg-card z-10">
                      <div className="flex items-center gap-2">
                        {r.logoUrl ? (
                          <img src={r.logoUrl} alt="" className="w-6 h-6 rounded object-contain bg-white/10 p-0.5" />
                        ) : (
                          <div className="w-6 h-6 rounded bg-muted flex items-center justify-center text-[10px] font-bold">{r.companyName[0]}</div>
                        )}
                        <span className="font-medium truncate max-w-[150px]">{r.companyName}</span>
                      </div>
                    </td>
                    {DOC_TYPES.map(dt => (
                      <td key={dt} className="px-3 py-3 text-center">
                        {cellIcon(r.docsByType[dt] ?? null)}
                      </td>
                    ))}
                    <td className="px-4 py-3">
                      <Link href={`/tprm/vendors/${r.id}`}>
                        <ChevronRight className="w-4 h-4 text-muted-foreground hover:text-foreground cursor-pointer" />
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </CardContent>
        </Card>
      )}

      {/* Legend */}
      <div className="flex items-center gap-4 text-xs text-muted-foreground">
        <span className="flex items-center gap-1"><CheckCircle2 className="w-3.5 h-3.5 text-green-400" />Valid</span>
        <span className="flex items-center gap-1"><Clock className="w-3.5 h-3.5 text-yellow-400" />Expiring ≤30d</span>
        <span className="flex items-center gap-1"><AlertTriangle className="w-3.5 h-3.5 text-red-400" />Expired</span>
        <span className="flex items-center gap-1"><XCircle className="w-3.5 h-3.5 text-red-400" />Missing</span>
      </div>
    </div>
  );
}
