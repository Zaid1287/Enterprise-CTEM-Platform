import { Link } from "wouter";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Shield, Lock, Building2, FileText, Package, ChevronRight } from "lucide-react";

export default function TprmUpgradePage() {
  return (
    <div className="flex flex-col items-center justify-center min-h-[60vh] p-8 text-center space-y-8">
      <div className="space-y-3">
        <div className="w-16 h-16 rounded-2xl bg-primary/10 flex items-center justify-center mx-auto">
          <Shield className="w-8 h-8 text-primary" />
        </div>
        <h1 className="text-2xl font-bold">Third Party Risk Management</h1>
        <p className="text-muted-foreground max-w-md">
          TPRM is not enabled for your organization. Contact your administrator to unlock continuous vendor risk monitoring.
        </p>
      </div>

      <div className="grid sm:grid-cols-2 gap-3 max-w-xl w-full text-left">
        {[
          { icon: Building2, title: "Vendor Risk Scoring", desc: "Continuous A–F risk grades from real DNS, TLS, HTTP, and Shodan data" },
          { icon: Package, title: "4th-Party Discovery", desc: "Auto-detect CDNs, analytics, and infrastructure providers used by your vendors" },
          { icon: FileText, title: "Compliance Tracking", desc: "SOC2, ISO 27001, PCI DSS, HIPAA compliance document management" },
          { icon: Lock, title: "SBOM & Supply Chain", desc: "Deep SBOM ingestion with OSV CVE enrichment for every component" },
        ].map(f => (
          <Card key={f.title} className="bg-card/60">
            <CardContent className="py-4 flex items-start gap-3">
              <f.icon className="w-5 h-5 text-primary shrink-0 mt-0.5" />
              <div>
                <p className="text-sm font-medium">{f.title}</p>
                <p className="text-xs text-muted-foreground mt-0.5">{f.desc}</p>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      <div className="flex gap-3">
        <Button asChild><Link href="/settings/tenant">Contact Administrator <ChevronRight className="w-4 h-4 ml-1" /></Link></Button>
        <Button variant="outline" asChild><Link href="/dashboard">Back to Dashboard</Link></Button>
      </div>
    </div>
  );
}
