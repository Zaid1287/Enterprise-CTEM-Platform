import { Crosshair } from "lucide-react";

export default function ThreatIntelIocsPage() {
  return (
    <div className="p-6 space-y-4">
      <div className="flex items-center gap-3">
        <Crosshair className="w-6 h-6 text-primary" />
        <h1 className="text-2xl font-bold">IOC Database</h1>
      </div>
      <p className="text-muted-foreground">Full IOC management coming in Task #152.</p>
    </div>
  );
}
