import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatDate(dateStr: string | null | undefined): string {
  if (!dateStr) return "—";
  return new Date(dateStr).toLocaleDateString("en-US", {
    year: "numeric", month: "short", day: "numeric",
  });
}

export function formatDateTime(dateStr: string | null | undefined): string {
  if (!dateStr) return "—";
  return new Date(dateStr).toLocaleString("en-US", {
    year: "numeric", month: "short", day: "numeric",
    hour: "2-digit", minute: "2-digit",
  });
}

export function severityBgColor(severity: string): string {
  switch (severity?.toLowerCase()) {
    case "critical": return "bg-red-500/15 text-red-400 border border-red-500/30";
    case "high": return "bg-orange-500/15 text-orange-400 border border-orange-500/30";
    case "medium": return "bg-yellow-500/15 text-yellow-400 border border-yellow-500/30";
    case "low": return "bg-green-500/15 text-green-400 border border-green-500/30";
    case "info": return "bg-blue-500/15 text-blue-400 border border-blue-500/30";
    default: return "bg-muted text-muted-foreground border border-border";
  }
}

export function statusBadgeClass(status: string): string {
  const s = status?.toLowerCase();
  if (s === "open" || s === "non_compliant" || s === "failed") return "bg-red-500/15 text-red-400 border border-red-500/30";
  if (s === "in_progress") return "bg-yellow-500/15 text-yellow-400 border border-yellow-500/30";
  if (s === "mitigated" || s === "compliant" || s === "completed" || s === "verified") return "bg-green-500/15 text-green-400 border border-green-500/30";
  if (s === "accepted_risk" || s === "not_applicable") return "bg-purple-500/15 text-purple-400 border border-purple-500/30";
  if (s === "false_positive" || s === "cancelled") return "bg-muted text-muted-foreground border border-border";
  if (s === "pending" || s === "queued" || s === "unverified") return "bg-blue-500/15 text-blue-400 border border-blue-500/30";
  if (s === "running") return "bg-yellow-500/15 text-yellow-400 border border-yellow-500/30";
  return "bg-muted text-muted-foreground border border-border";
}

export function riskLevelBg(level: string): string {
  switch (level?.toLowerCase()) {
    case "critical": return "bg-red-500/15 text-red-400 border border-red-500/30";
    case "high": return "bg-orange-500/15 text-orange-400 border border-orange-500/30";
    case "medium": return "bg-yellow-500/15 text-yellow-400 border border-yellow-500/30";
    case "low": return "bg-green-500/15 text-green-400 border border-green-500/30";
    default: return "bg-muted text-muted-foreground border border-border";
  }
}

export function capitalize(str: string): string {
  if (!str) return "";
  return str.charAt(0).toUpperCase() + str.slice(1).replace(/_/g, " ");
}
