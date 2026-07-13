import { Server } from "lucide-react";

export default function ThreatIntelC2Page() {
  return (
    <div className="p-6 space-y-4">
      <div className="flex items-center gap-3">
        <Server className="w-6 h-6 text-primary" />
        <h1 className="text-2xl font-bold">C2 Infrastructure</h1>
      </div>
      <p className="text-muted-foreground">Full C2 server map coming in Task #152.</p>
    </div>
  );
}
