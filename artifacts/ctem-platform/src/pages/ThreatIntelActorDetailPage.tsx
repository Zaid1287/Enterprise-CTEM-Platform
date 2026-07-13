import { Users } from "lucide-react";

export default function ThreatIntelActorDetailPage() {
  return (
    <div className="p-6 space-y-4">
      <div className="flex items-center gap-3">
        <Users className="w-6 h-6 text-primary" />
        <h1 className="text-2xl font-bold">Threat Actor Detail</h1>
      </div>
      <p className="text-muted-foreground">Full actor detail coming in Task #152.</p>
    </div>
  );
}
