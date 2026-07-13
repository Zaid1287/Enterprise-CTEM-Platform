import { Target } from "lucide-react";

export default function ThreatIntelCampaignsPage() {
  return (
    <div className="p-6 space-y-4">
      <div className="flex items-center gap-3">
        <Target className="w-6 h-6 text-primary" />
        <h1 className="text-2xl font-bold">Campaigns</h1>
      </div>
      <p className="text-muted-foreground">Full campaign tracking coming in Task #152.</p>
    </div>
  );
}
