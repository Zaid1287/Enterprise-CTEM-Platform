import { AlertTriangle } from "lucide-react";

export default function ThreatIntelCvesPage() {
  return (
    <div className="p-6 space-y-4">
      <div className="flex items-center gap-3">
        <AlertTriangle className="w-6 h-6 text-primary" />
        <h1 className="text-2xl font-bold">CVE Intelligence</h1>
      </div>
      <p className="text-muted-foreground">Full CVE intel coming in Task #152.</p>
    </div>
  );
}
