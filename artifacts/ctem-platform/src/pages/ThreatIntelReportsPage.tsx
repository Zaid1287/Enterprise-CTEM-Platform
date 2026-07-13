import { FileBarChart2 } from "lucide-react";

export default function ThreatIntelReportsPage() {
  return (
    <div className="p-6 space-y-4">
      <div className="flex items-center gap-3">
        <FileBarChart2 className="w-6 h-6 text-primary" />
        <h1 className="text-2xl font-bold">Threat Intel Reports</h1>
      </div>
      <p className="text-muted-foreground">Full TI reporting coming in Task #152.</p>
    </div>
  );
}
