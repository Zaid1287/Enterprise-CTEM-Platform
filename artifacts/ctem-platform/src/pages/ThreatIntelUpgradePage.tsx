import { Shield, Zap, Globe, Search, AlertTriangle, ChevronRight } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useLocation } from "wouter";

export default function ThreatIntelUpgradePage() {
  const [, navigate] = useLocation();
  return (
    <div className="flex flex-col items-center justify-center min-h-[70vh] px-4">
      <div className="max-w-2xl w-full text-center space-y-6">
        <div className="flex justify-center">
          <div className="p-4 rounded-2xl bg-primary/10 border border-primary/20">
            <Shield className="w-12 h-12 text-primary" />
          </div>
        </div>
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Threat Intelligence</h1>
          <p className="mt-3 text-muted-foreground text-lg">
            Proactive threat intelligence with real-time IOC feeds, threat actor tracking, C2 infrastructure mapping, and AI-powered correlation against your attack surface.
          </p>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-left">
          {[
            { icon: Globe, title: "Live IOC Feeds", desc: "AlienVault OTX, AbuseIPDB, ThreatFox, MalwareBazaar, URLhaus, and more" },
            { icon: Search, title: "Threat Actor Profiles", desc: "MITRE ATT&CK-aligned actor intelligence with TTP mapping and kill chains" },
            { icon: Zap, title: "ASM Correlation", desc: "Automatically correlates findings with known IOCs, campaigns, and CVE exploitation" },
            { icon: AlertTriangle, title: "C2 Infrastructure", desc: "Real-time C2 server tracking with geo-intelligence and malware family attribution" },
          ].map(({ icon: Icon, title, desc }) => (
            <div key={title} className="flex gap-3 p-4 rounded-xl border bg-card">
              <Icon className="w-5 h-5 text-primary mt-0.5 shrink-0" />
              <div>
                <p className="font-semibold text-sm">{title}</p>
                <p className="text-xs text-muted-foreground mt-0.5">{desc}</p>
              </div>
            </div>
          ))}
        </div>
        <div className="flex flex-col sm:flex-row gap-3 justify-center">
          <Button onClick={() => navigate("/packages")} className="gap-2">
            Upgrade to enable Threat Intelligence <ChevronRight className="w-4 h-4" />
          </Button>
          <Button variant="outline" onClick={() => navigate("/settings/tenant")}>
            Contact Administrator
          </Button>
        </div>
      </div>
    </div>
  );
}
