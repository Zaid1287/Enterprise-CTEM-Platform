import { Newspaper } from "lucide-react";

export default function ThreatIntelNewsPage() {
  return (
    <div className="p-6 space-y-4">
      <div className="flex items-center gap-3">
        <Newspaper className="w-6 h-6 text-primary" />
        <h1 className="text-2xl font-bold">Threat News</h1>
      </div>
      <p className="text-muted-foreground">Full threat news feed coming in Task #152.</p>
    </div>
  );
}
