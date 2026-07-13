import { Eye } from "lucide-react";

export default function ThreatIntelDarkWebPage() {
  return (
    <div className="p-6 space-y-4">
      <div className="flex items-center gap-3">
        <Eye className="w-6 h-6 text-primary" />
        <h1 className="text-2xl font-bold">Dark Web Monitoring</h1>
      </div>
      <p className="text-muted-foreground">Full dark web monitoring coming in Task #152.</p>
    </div>
  );
}
