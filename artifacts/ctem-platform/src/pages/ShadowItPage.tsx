import { useState, useCallback, useMemo } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter,
} from "@/components/ui/dialog";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import {
  Eye, EyeOff, Cloud, AlertTriangle, Globe, Terminal, Cpu, Server,
  RefreshCw, Search, CheckCircle, XCircle, Clock, ShieldAlert,
  Play, Layers, Mail, Activity, Lock, Wifi, Package,
  ExternalLink, FileText, Loader2, Filter, Plus,
  ChevronDown, ChevronRight, ArrowUpDown, Network, Radio,
  Shield, Fingerprint, ScanSearch,
} from "lucide-react";
import { apiFetch } from "@/lib/apiFetch";
import { useToast } from "@/hooks/use-toast";
import { useAuth } from "@/hooks/useAuth";
import { cn } from "@/lib/utils";

// ── Types ────────────────────────────────────────────────────────────────────

interface ShadowItSummary {
  totalAssets: number;
  totalSaasApps: number;
  pendingReview: number;
  approved: number;
  remediated: number;
  byRisk: Record<string, number>;
  byType: Record<string, number>;
  saasByStatus: Record<string, number>;
}

interface ShadowAsset {
  id: number;
  tenantId: number;
  name: string;
  type: string;
  classification: string;
  source: string;
  parentAssetId: number | null;
  relatedScanId: number | null;
  evidence: Record<string, unknown> | null;
  riskScore: number | null;
  riskLevel: string;
  hasOpenPorts: boolean;
  hasAdminPanel: boolean;
  hasAuthBypass: boolean;
  isPubliclyAccessible: boolean;
  certFirstSeen: string | null;
  status: string;
  reviewedBy: number | null;
  reviewedAt: string | null;
  reviewNote: string | null;
  firstSeenAt: string;
  lastSeenAt: string;
}

interface ShadowSaasApp {
  id: number;
  tenantId: number;
  appName: string;
  appCategory: string | null;
  idpSource: string;
  appId: string | null;
  userCount: number;
  isSanctioned: boolean;
  riskRating: string;
  evidence: Record<string, unknown> | null;
  status: string;
  discoveredViaAssetId: number | null;
  createdAt: string;
}

// ── Metadata Maps ─────────────────────────────────────────────────────────────

const RISK: Record<string, { label: string; dot: string; badge: string; bar: string; text: string; borderL: string }> = {
  critical: { label: "Critical", dot: "bg-red-500",    badge: "bg-red-500/15 text-red-400 border-red-500/30",    bar: "bg-red-500",    text: "text-red-400",    borderL: "border-l-red-500" },
  high:     { label: "High",     dot: "bg-orange-500", badge: "bg-orange-500/15 text-orange-400 border-orange-500/30", bar: "bg-orange-500", text: "text-orange-400", borderL: "border-l-orange-500" },
  medium:   { label: "Medium",   dot: "bg-yellow-500", badge: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30", bar: "bg-yellow-500", text: "text-yellow-400", borderL: "border-l-yellow-500" },
  low:      { label: "Low",      dot: "bg-blue-500",   badge: "bg-blue-500/15 text-blue-400 border-blue-500/30",   bar: "bg-blue-500",   text: "text-blue-400",   borderL: "border-l-blue-500" },
  info:     { label: "Info",     dot: "bg-slate-400",  badge: "bg-slate-500/15 text-slate-400 border-slate-500/30", bar: "bg-slate-500",  text: "text-slate-400",  borderL: "border-l-slate-500" },
};

const STATUS: Record<string, { label: string; icon: React.ReactNode; cls: string; pill: string }> = {
  new:            { label: "New",            icon: <AlertTriangle className="w-3 h-3" />, cls: "bg-blue-500/15 text-blue-400 border-blue-500/30",   pill: "bg-blue-500/15 text-blue-400 hover:bg-blue-500/25 border-blue-500/30" },
  under_review:   { label: "Reviewing",      icon: <Clock className="w-3 h-3" />,         cls: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30", pill: "bg-yellow-500/15 text-yellow-400 hover:bg-yellow-500/25 border-yellow-500/30" },
  approved:       { label: "Approved",       icon: <CheckCircle className="w-3 h-3" />,   cls: "bg-green-500/15 text-green-400 border-green-500/30",  pill: "bg-green-500/15 text-green-400 hover:bg-green-500/25 border-green-500/30" },
  remediated:     { label: "Remediated",     icon: <CheckCircle className="w-3 h-3" />,   cls: "bg-emerald-500/15 text-emerald-400 border-emerald-500/30", pill: "bg-emerald-500/15 text-emerald-400 hover:bg-emerald-500/25 border-emerald-500/30" },
  false_positive: { label: "False Positive", icon: <XCircle className="w-3 h-3" />,       cls: "bg-slate-500/15 text-slate-400 border-slate-500/30",  pill: "bg-slate-500/15 text-slate-400 hover:bg-slate-500/25 border-slate-500/30" },
};

const CLASS: Record<string, { label: string; cls: string }> = {
  forgotten:          { label: "Forgotten",    cls: "bg-orange-500/10 text-orange-400 border-orange-500/20" },
  rogue:              { label: "Rogue",         cls: "bg-red-500/10 text-red-400 border-red-500/20" },
  development:        { label: "Dev Asset",     cls: "bg-blue-500/10 text-blue-400 border-blue-500/20" },
  saas:               { label: "SaaS",          cls: "bg-purple-500/10 text-purple-400 border-purple-500/20" },
  cloud:              { label: "Cloud",         cls: "bg-sky-500/10 text-sky-400 border-sky-500/20" },
  unauthorized_stack: { label: "Unauth Stack",  cls: "bg-yellow-500/10 text-yellow-400 border-yellow-500/20" },
};

const TYPE_ICONS: Record<string, React.ReactNode> = {
  subdomain:          <Globe className="w-3.5 h-3.5 text-blue-400" />,
  cloud_bucket:       <Cloud className="w-3.5 h-3.5 text-sky-400" />,
  email_service:      <Mail className="w-3.5 h-3.5 text-purple-400" />,
  admin_panel:        <Terminal className="w-3.5 h-3.5 text-red-400" />,
  shadow_service:     <Server className="w-3.5 h-3.5 text-orange-400" />,
  unauthorized_tech:  <Cpu className="w-3.5 h-3.5 text-yellow-400" />,
  ip_asset:           <Activity className="w-3.5 h-3.5 text-slate-400" />,
};

// ── Small Components ──────────────────────────────────────────────────────────

function RiskBadge({ level }: { level: string }) {
  const m = RISK[level] ?? RISK.info;
  return (
    <span className={cn("inline-flex items-center gap-1 text-[10px] font-semibold px-2 py-0.5 rounded-full border", m.badge)}>
      <span className={cn("h-1.5 w-1.5 rounded-full shrink-0", m.dot)} />
      {m.label}
    </span>
  );
}

function StatusBadge({ status }: { status: string }) {
  const m = STATUS[status] ?? { label: status, icon: null, cls: "bg-slate-500/15 text-slate-400 border-slate-500/30" };
  return (
    <span className={cn("inline-flex items-center gap-1 text-[10px] font-medium px-2 py-0.5 rounded-full border", m.cls)}>
      {m.icon}{m.label}
    </span>
  );
}

function ClassBadge({ cls }: { cls: string }) {
  const m = CLASS[cls] ?? { label: cls, cls: "bg-slate-500/10 text-slate-400 border-slate-500/20" };
  return (
    <span className={cn("inline-flex text-[10px] font-medium px-1.5 py-0.5 rounded border", m.cls)}>
      {m.label}
    </span>
  );
}

function RiskScoreBar({ score, level }: { score: number | null; level: string }) {
  const m = RISK[level] ?? RISK.info;
  const s = score != null ? Math.round(score) : 0;
  return (
    <div className="flex items-center gap-2 min-w-[80px]">
      <div className="flex-1 h-1.5 rounded-full bg-accent overflow-hidden">
        <div className={cn("h-full rounded-full", m.bar)} style={{ width: `${s}%` }} />
      </div>
      <span className={cn("text-[11px] font-bold tabular-nums w-6 text-right shrink-0", m.text)}>
        {score != null ? s : "—"}
      </span>
    </div>
  );
}

function FlagChips({ asset }: { asset: ShadowAsset }) {
  const flags: { label: string; cls: string }[] = [];
  if (asset.hasOpenPorts)        flags.push({ label: "Port",   cls: "bg-orange-500/10 text-orange-400 border-orange-500/20" });
  if (asset.hasAdminPanel)       flags.push({ label: "Admin",  cls: "bg-red-500/10 text-red-400 border-red-500/20" });
  if (asset.hasAuthBypass)       flags.push({ label: "No Auth", cls: "bg-red-500/10 text-red-400 border-red-500/20" });
  if (asset.isPubliclyAccessible) flags.push({ label: "Public", cls: "bg-blue-500/10 text-blue-400 border-blue-500/20" });
  if (flags.length === 0) return <span className="text-muted-foreground/40 text-[10px]">—</span>;
  return (
    <div className="flex flex-wrap gap-1">
      {flags.map(f => (
        <span key={f.label} className={cn("text-[9px] font-semibold px-1.5 py-0.5 rounded border", f.cls)}>{f.label}</span>
      ))}
    </div>
  );
}

function fmtDate(d: string | null) {
  if (!d) return "—";
  return new Date(d).toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" });
}

function fmtRelative(d: string | null) {
  if (!d) return "—";
  const ms = Date.now() - new Date(d).getTime();
  const mins = Math.floor(ms / 60000);
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

// ── Asset Table Row ───────────────────────────────────────────────────────────

function AssetRow({
  asset, canTriage, onTriage, onEvidence,
}: {
  asset: ShadowAsset;
  canTriage: boolean;
  onTriage: (a: ShadowAsset) => void;
  onEvidence: (a: ShadowAsset) => void;
}) {
  const [expanded, setExpanded] = useState(false);
  const riskM = RISK[asset.riskLevel] ?? RISK.info;

  return (
    <>
      <tr
        className={cn(
          "group border-b border-border/50 hover:bg-accent/30 transition-colors cursor-pointer",
          expanded && "bg-accent/20",
        )}
        onClick={() => setExpanded(e => !e)}
      >
        {/* Expand toggle */}
        <td className="pl-4 pr-2 py-3 w-8">
          <div className={cn("h-4 w-4 rounded transition-transform text-muted-foreground", expanded && "rotate-90")}>
            <ChevronRight className="h-4 w-4" />
          </div>
        </td>

        {/* Risk indicator strip + name */}
        <td className="py-3 pr-4 max-w-[240px]">
          <div className="flex items-center gap-2.5">
            <div className={cn("h-8 w-0.5 rounded-full shrink-0", riskM.bar)} />
            <div className="p-1.5 rounded-md bg-accent/60 shrink-0">
              {TYPE_ICONS[asset.type] ?? <Layers className="w-3.5 h-3.5 text-slate-400" />}
            </div>
            <div className="min-w-0">
              <p className="font-mono text-xs font-semibold truncate leading-tight" title={asset.name}>
                {asset.name}
              </p>
              <p className="text-[10px] text-muted-foreground capitalize mt-0.5">
                {asset.source.replace(/_/g, " ")}
              </p>
            </div>
          </div>
        </td>

        {/* Type */}
        <td className="py-3 pr-4">
          <span className="text-xs text-muted-foreground capitalize">
            {asset.type.replace(/_/g, " ")}
          </span>
        </td>

        {/* Classification */}
        <td className="py-3 pr-4">
          <ClassBadge cls={asset.classification} />
        </td>

        {/* Risk score */}
        <td className="py-3 pr-6 min-w-[120px]">
          <RiskScoreBar score={asset.riskScore} level={asset.riskLevel} />
        </td>

        {/* Risk badge */}
        <td className="py-3 pr-4">
          <RiskBadge level={asset.riskLevel} />
        </td>

        {/* Status */}
        <td className="py-3 pr-4">
          <StatusBadge status={asset.status} />
        </td>

        {/* Flags */}
        <td className="py-3 pr-4 hidden lg:table-cell">
          <FlagChips asset={asset} />
        </td>

        {/* First seen */}
        <td className="py-3 pr-4 hidden xl:table-cell">
          <span className="text-[11px] text-muted-foreground whitespace-nowrap">{fmtRelative(asset.firstSeenAt)}</span>
        </td>

        {/* Actions */}
        <td className="py-3 pr-4" onClick={e => e.stopPropagation()}>
          <div className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
            <Button
              variant="ghost" size="sm"
              className="h-7 px-2 text-[10px] gap-1 text-muted-foreground hover:text-foreground"
              onClick={() => onEvidence(asset)}
            >
              <FileText className="h-3 w-3" /> Evidence
            </Button>
            {canTriage && (
              <Button
                size="sm"
                className={cn(
                  "h-7 px-2 text-[10px] gap-1",
                  asset.status === "new"
                    ? "bg-primary text-primary-foreground hover:bg-primary/90"
                    : "variant-outline border border-border text-muted-foreground hover:text-foreground",
                )}
                onClick={() => onTriage(asset)}
              >
                <ShieldAlert className="h-3 w-3" />
                {asset.status === "new" ? "Triage" : "Update"}
              </Button>
            )}
          </div>
        </td>
      </tr>

      {/* Expanded details row */}
      {expanded && (
        <tr className="bg-accent/10 border-b border-border/30">
          <td colSpan={10} className="px-6 py-4">
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-xs">
              <div>
                <p className="text-[10px] text-muted-foreground uppercase tracking-wide mb-1">First Seen</p>
                <p className="font-medium">{fmtDate(asset.firstSeenAt)}</p>
              </div>
              <div>
                <p className="text-[10px] text-muted-foreground uppercase tracking-wide mb-1">Last Seen</p>
                <p className="font-medium">{fmtDate(asset.lastSeenAt)}</p>
              </div>
              <div>
                <p className="text-[10px] text-muted-foreground uppercase tracking-wide mb-1">Cert First Seen</p>
                <p className="font-medium">{fmtDate(asset.certFirstSeen)}</p>
              </div>
              <div>
                <p className="text-[10px] text-muted-foreground uppercase tracking-wide mb-1">Source</p>
                <p className="font-medium capitalize">{asset.source.replace(/_/g, " ")}</p>
              </div>
              {asset.reviewNote && (
                <div className="col-span-2 md:col-span-4">
                  <p className="text-[10px] text-muted-foreground uppercase tracking-wide mb-1">Review Note</p>
                  <p className="font-medium text-muted-foreground italic">{asset.reviewNote}</p>
                </div>
              )}
              {asset.evidence && Object.keys(asset.evidence).length > 0 && (
                <div className="col-span-2 md:col-span-4">
                  <p className="text-[10px] text-muted-foreground uppercase tracking-wide mb-2">Evidence</p>
                  <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
                    {Object.entries(asset.evidence).slice(0, 9).map(([k, v]) => (
                      <div key={k} className="bg-card border border-border rounded-md px-2.5 py-1.5">
                        <p className="text-[9px] text-muted-foreground uppercase tracking-wide">{k.replace(/_/g, " ")}</p>
                        <p className="text-[11px] font-medium mt-0.5 break-all">
                          {typeof v === "boolean" ? (v ? "Yes" : "No") : typeof v === "object" ? JSON.stringify(v).slice(0, 60) : String(v ?? "—")}
                        </p>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

// ── SaaS Table Row ────────────────────────────────────────────────────────────

function SaasRow({
  app, canTriage, onSanction,
}: {
  app: ShadowSaasApp;
  canTriage: boolean;
  onSanction: (id: number, value: boolean) => void;
}) {
  const [expanded, setExpanded] = useState(false);

  return (
    <>
      <tr
        className={cn(
          "group border-b border-border/50 hover:bg-accent/30 transition-colors cursor-pointer",
          expanded && "bg-accent/20",
        )}
        onClick={() => setExpanded(e => !e)}
      >
        <td className="pl-4 pr-2 py-3 w-8">
          <div className={cn("h-4 w-4 rounded transition-transform text-muted-foreground", expanded && "rotate-90")}>
            <ChevronRight className="h-4 w-4" />
          </div>
        </td>

        {/* App name */}
        <td className="py-3 pr-4">
          <div className="flex items-center gap-2.5">
            <div className="h-8 w-8 rounded-lg bg-gradient-to-br from-purple-500/20 to-purple-500/5 border border-purple-500/20 flex items-center justify-center text-xs font-bold text-purple-400 shrink-0">
              {app.appName.slice(0, 2).toUpperCase()}
            </div>
            <div className="min-w-0">
              <p className="text-xs font-semibold truncate">{app.appName}</p>
              <p className="text-[10px] text-muted-foreground capitalize">{app.appCategory ?? "Other"}</p>
            </div>
          </div>
        </td>

        {/* IdP Source */}
        <td className="py-3 pr-4">
          <span className="text-[10px] border border-border rounded px-1.5 py-0.5 text-muted-foreground capitalize">
            {app.idpSource.replace(/_/g, " ")}
          </span>
        </td>

        {/* Risk */}
        <td className="py-3 pr-4">
          <RiskBadge level={app.riskRating} />
        </td>

        {/* Sanction status */}
        <td className="py-3 pr-4">
          {app.isSanctioned ? (
            <span className="inline-flex items-center gap-1 text-[10px] font-medium px-2 py-0.5 rounded-full border bg-green-500/15 text-green-400 border-green-500/30">
              <CheckCircle className="h-2.5 w-2.5" /> Sanctioned
            </span>
          ) : (
            <span className="inline-flex items-center gap-1 text-[10px] font-medium px-2 py-0.5 rounded-full border bg-orange-500/15 text-orange-400 border-orange-500/30">
              <AlertTriangle className="h-2.5 w-2.5" /> Unsanctioned
            </span>
          )}
        </td>

        {/* Status */}
        <td className="py-3 pr-4">
          <StatusBadge status={app.status} />
        </td>

        {/* Discovered */}
        <td className="py-3 pr-4 hidden xl:table-cell">
          <span className="text-[11px] text-muted-foreground">{fmtDate(app.createdAt)}</span>
        </td>

        {/* Sanction toggle */}
        <td className="py-3 pr-4" onClick={e => e.stopPropagation()}>
          {canTriage && (
            <div className="flex items-center gap-2 opacity-0 group-hover:opacity-100 transition-opacity">
              <Label htmlFor={`sanction-${app.id}`} className="text-[10px] text-muted-foreground cursor-pointer">
                Sanctioned
              </Label>
              <Switch
                id={`sanction-${app.id}`}
                checked={app.isSanctioned}
                onCheckedChange={v => onSanction(app.id, v)}
              />
            </div>
          )}
        </td>
      </tr>

      {expanded && (
        <tr className="bg-accent/10 border-b border-border/30">
          <td colSpan={8} className="px-6 py-4">
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-xs">
              <div>
                <p className="text-[10px] text-muted-foreground uppercase tracking-wide mb-1">App ID</p>
                <p className="font-mono font-medium">{app.appId ?? "—"}</p>
              </div>
              <div>
                <p className="text-[10px] text-muted-foreground uppercase tracking-wide mb-1">User Count</p>
                <p className="font-medium">{app.userCount}</p>
              </div>
              <div>
                <p className="text-[10px] text-muted-foreground uppercase tracking-wide mb-1">Discovered Via</p>
                <p className="font-medium capitalize">{app.idpSource.replace(/_/g, " ")}</p>
              </div>
              <div>
                <p className="text-[10px] text-muted-foreground uppercase tracking-wide mb-1">Discovered At</p>
                <p className="font-medium">{fmtDate(app.createdAt)}</p>
              </div>
              {app.evidence && Object.keys(app.evidence).length > 0 && (
                <div className="col-span-2 md:col-span-4">
                  <p className="text-[10px] text-muted-foreground uppercase tracking-wide mb-2">Evidence</p>
                  <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
                    {Object.entries(app.evidence).slice(0, 6).map(([k, v]) => (
                      <div key={k} className="bg-card border border-border rounded-md px-2.5 py-1.5">
                        <p className="text-[9px] text-muted-foreground uppercase tracking-wide">{k.replace(/_/g, " ")}</p>
                        <p className="text-[11px] font-medium mt-0.5 break-all">
                          {typeof v === "boolean" ? (v ? "Yes" : "No") : typeof v === "object" ? JSON.stringify(v).slice(0, 60) : String(v ?? "—")}
                        </p>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

// ── Main Page ─────────────────────────────────────────────────────────────────

export default function ShadowItPage() {
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const { user } = useAuth();
  const canTriage = ["admin", "super_admin", "manager"].includes(user?.role ?? "");

  // Filter state
  const [assetStatus, setAssetStatus] = useState("new");
  const [assetRisk,   setAssetRisk]   = useState("");
  const [assetType,   setAssetType]   = useState("");
  const [assetSearch, setAssetSearch] = useState("");
  const [assetPage,   setAssetPage]   = useState(0);
  const PAGE = 50;

  const [saasStatus, setSaasStatus]   = useState("");
  const [saasSearch, setSaasSearch]   = useState("");

  // Dialog state
  const [triageItem,   setTriageItem]   = useState<ShadowAsset | null>(null);
  const [triageStatus, setTriageStatus] = useState("approved");
  const [triageRisk,   setTriageRisk]   = useState("");
  const [triageNote,   setTriageNote]   = useState("");
  const [evidenceItem, setEvidenceItem] = useState<ShadowAsset | null>(null);

  const [scanRunning, setScanRunning] = useState(false);

  // ── Queries ───────────────────────────────────────────────────────────────

  const { data: summary, isLoading: summaryLoading } = useQuery<ShadowItSummary>({
    queryKey: ["shadow-it-summary"],
    queryFn: () => apiFetch<ShadowItSummary>("/api/shadow-it/summary"),
    refetchInterval: 30_000,
    staleTime: 20_000,
  });

  const assetParams = new URLSearchParams({
    limit: String(PAGE),
    offset: String(assetPage * PAGE),
    ...(assetStatus ? { status: assetStatus } : {}),
    ...(assetRisk   ? { riskLevel: assetRisk } : {}),
    ...(assetType   ? { type: assetType } : {}),
  });

  const {
    data: assetsData, isLoading: assetsLoading,
    refetch: refetchAssets, isFetching: assetsFetching,
  } = useQuery<{ items: ShadowAsset[]; total: number }>({
    queryKey: ["shadow-it-assets", assetStatus, assetRisk, assetType, assetPage],
    queryFn: () => apiFetch<{ items: ShadowAsset[]; total: number }>(`/api/shadow-it/assets?${assetParams}`),
    staleTime: 20_000,
  });

  const saasParams = new URLSearchParams({
    limit: "200",
    ...(saasStatus ? { status: saasStatus } : {}),
  });

  const { data: saasData, isLoading: saasLoading, refetch: refetchSaas } = useQuery<{ items: ShadowSaasApp[]; total: number }>({
    queryKey: ["shadow-it-saas", saasStatus],
    queryFn: () => apiFetch<{ items: ShadowSaasApp[]; total: number }>(`/api/shadow-it/saas?${saasParams}`),
    staleTime: 20_000,
  });

  // ── Mutations ─────────────────────────────────────────────────────────────

  const triageMutation = useMutation({
    mutationFn: ({ id, status, reviewNote, riskLevel }: {
      id: number; status: string; reviewNote: string; riskLevel?: string;
    }) =>
      apiFetch(`/api/shadow-it/assets/${id}/triage`, {
        method: "PATCH",
        body: JSON.stringify({ status, reviewNote, ...(riskLevel ? { riskLevel } : {}) }),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["shadow-it-assets"] });
      queryClient.invalidateQueries({ queryKey: ["shadow-it-summary"] });
      setTriageItem(null);
      toast({ title: "Asset triaged", description: "Shadow IT asset updated successfully." });
    },
    onError: () => toast({ title: "Update failed", variant: "destructive" }),
  });

  const saasMutation = useMutation({
    mutationFn: ({ id, isSanctioned }: { id: number; isSanctioned: boolean }) =>
      apiFetch(`/api/shadow-it/saas/${id}`, { method: "PATCH", body: JSON.stringify({ isSanctioned }) }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["shadow-it-saas"] });
      queryClient.invalidateQueries({ queryKey: ["shadow-it-summary"] });
    },
    onError: () => toast({ title: "Update failed", variant: "destructive" }),
  });

  const runScan = useCallback(async () => {
    setScanRunning(true);
    try {
      await apiFetch("/api/shadow-it/scan", { method: "POST", body: JSON.stringify({}) });
      toast({ title: "Shadow IT scan started", description: "Discovery running in background — results will appear shortly." });
      setTimeout(() => {
        queryClient.invalidateQueries({ queryKey: ["shadow-it-assets"] });
        queryClient.invalidateQueries({ queryKey: ["shadow-it-summary"] });
        setScanRunning(false);
      }, 8_000);
    } catch {
      toast({ title: "Scan failed", variant: "destructive" });
      setScanRunning(false);
    }
  }, [queryClient, toast]);

  const openTriage = (asset: ShadowAsset) => {
    setTriageItem(asset);
    setTriageStatus(asset.status === "new" ? "approved" : asset.status);
    setTriageRisk(asset.riskLevel);
    setTriageNote(asset.reviewNote ?? "");
  };

  // Client-side search filter
  const assets = useMemo(() =>
    (assetsData?.items ?? []).filter(a =>
      !assetSearch || a.name.toLowerCase().includes(assetSearch.toLowerCase())
    ),
  [assetsData, assetSearch]);

  const saasApps = useMemo(() =>
    (saasData?.items ?? []).filter(a =>
      !saasSearch || a.appName.toLowerCase().includes(saasSearch.toLowerCase())
    ),
  [saasData, saasSearch]);

  const totalPages = Math.ceil((assetsData?.total ?? 0) / PAGE);

  // Risk distribution data from summary
  const riskDistribution = summary ? ["critical","high","medium","low","info"].map(level => ({
    level, count: summary.byRisk[level] ?? 0,
    pct: summary.totalAssets > 0 ? ((summary.byRisk[level] ?? 0) / summary.totalAssets) * 100 : 0,
  })) : [];

  // Type distribution
  const typeDistribution = summary ? Object.entries(summary.byType)
    .sort(([,a],[,b]) => (b as number) - (a as number))
    .slice(0, 5)
    .map(([type, count]) => ({ type, count: count as number }))
  : [];

  // ── KPI metrics ───────────────────────────────────────────────────────────
  const kpis = [
    {
      label: "Total Discovered",
      value: (summary?.totalAssets ?? 0) + (summary?.totalSaasApps ?? 0),
      sub: `${summary?.totalAssets ?? 0} assets · ${summary?.totalSaasApps ?? 0} SaaS`,
      icon: <ScanSearch className="h-4.5 w-4.5" />,
      borderColor: "border-l-slate-400",
      iconBg: "bg-slate-500/10 text-slate-300",
    },
    {
      label: "Pending Review",
      value: summary?.pendingReview ?? 0,
      sub: "Require triage",
      icon: <AlertTriangle className="h-4.5 w-4.5" />,
      borderColor: (summary?.pendingReview ?? 0) > 0 ? "border-l-orange-500" : "border-l-slate-400",
      iconBg: (summary?.pendingReview ?? 0) > 0 ? "bg-orange-500/10 text-orange-400" : "bg-slate-500/10 text-slate-400",
      valueColor: (summary?.pendingReview ?? 0) > 0 ? "text-orange-400" : undefined,
    },
    {
      label: "Critical Risk",
      value: summary?.byRisk?.critical ?? 0,
      sub: "Immediate action needed",
      icon: <ShieldAlert className="h-4.5 w-4.5" />,
      borderColor: (summary?.byRisk?.critical ?? 0) > 0 ? "border-l-red-500" : "border-l-slate-400",
      iconBg: (summary?.byRisk?.critical ?? 0) > 0 ? "bg-red-500/10 text-red-400" : "bg-slate-500/10 text-slate-400",
      valueColor: (summary?.byRisk?.critical ?? 0) > 0 ? "text-red-400" : undefined,
    },
    {
      label: "Approved / Closed",
      value: (summary?.approved ?? 0) + (summary?.remediated ?? 0),
      sub: "Reviewed & resolved",
      icon: <CheckCircle className="h-4.5 w-4.5" />,
      borderColor: "border-l-green-500",
      iconBg: "bg-green-500/10 text-green-400",
      valueColor: "text-green-400",
    },
  ];

  // ── Status quick-filter pills ─────────────────────────────────────────────
  const STATUS_FILTERS = [
    { value: "",               label: "All" },
    { value: "new",            label: `New${summary?.pendingReview ? ` (${summary.pendingReview})` : ""}` },
    { value: "under_review",   label: "Reviewing" },
    { value: "approved",       label: "Approved" },
    { value: "remediated",     label: "Remediated" },
    { value: "false_positive", label: "False Positive" },
  ];

  // ── Render ────────────────────────────────────────────────────────────────

  return (
    <div className="flex flex-col h-full">

      {/* ── Page Header ──────────────────────────────────────────────────────── */}
      <div className="border-b border-border/50 bg-card">
        <div className="h-0.5 bg-gradient-to-r from-orange-500 via-amber-500 to-yellow-500" />
        <div className="px-6 py-4 flex items-center justify-between gap-4 flex-wrap">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-orange-500/15 border border-orange-500/25">
              <EyeOff className="h-5 w-5 text-orange-400" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-lg font-bold tracking-tight">Shadow IT Discovery</h1>
                {(assetsFetching || summaryLoading) && (
                  <Loader2 className="h-3.5 w-3.5 animate-spin text-muted-foreground" />
                )}
              </div>
              <p className="text-xs text-muted-foreground mt-0.5">
                Assets, services, and SaaS apps discovered outside your registered inventory
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Button
              variant="outline" size="sm" className="h-8 gap-1.5"
              onClick={() => { refetchAssets(); refetchSaas(); }}
              disabled={assetsFetching}
            >
              <RefreshCw className={cn("h-3.5 w-3.5", assetsFetching && "animate-spin")} />
              Refresh
            </Button>
            {canTriage && (
              <Button onClick={runScan} disabled={scanRunning} size="sm" className="h-8 gap-1.5 bg-orange-500 hover:bg-orange-600 text-white">
                {scanRunning ? <RefreshCw className="h-3.5 w-3.5 animate-spin" /> : <Play className="h-3.5 w-3.5" />}
                {scanRunning ? "Scanning…" : "Run Discovery"}
              </Button>
            )}
          </div>
        </div>
      </div>

      {/* ── KPI Metrics Bar ──────────────────────────────────────────────────── */}
      <div className="px-6 py-4 border-b border-border/40 bg-card/50">
        <div className="grid grid-cols-2 xl:grid-cols-4 gap-4">
          {kpis.map(k => (
            <div key={k.label} className={cn(
              "bg-card border border-border rounded-xl p-4 border-l-4 flex items-center gap-3",
              k.borderColor,
            )}>
              <div className={cn("p-2 rounded-lg shrink-0", k.iconBg)}>{k.icon}</div>
              <div className="min-w-0">
                <p className="text-[10px] text-muted-foreground uppercase tracking-wider font-semibold">{k.label}</p>
                <p className={cn("text-2xl font-bold tabular-nums leading-none mt-1", k.valueColor)}>
                  {summaryLoading ? <span className="text-muted-foreground/30 text-lg">—</span> : k.value}
                </p>
                <p className="text-[10px] text-muted-foreground mt-0.5 truncate">{k.sub}</p>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* ── Pending Alert Banner ──────────────────────────────────────────────── */}
      {(summary?.pendingReview ?? 0) > 0 && (
        <div className="mx-6 mt-4 rounded-xl border border-orange-500/25 bg-orange-500/8 px-4 py-3 flex items-center justify-between gap-4 flex-wrap">
          <div className="flex items-center gap-3">
            <div className="p-1.5 rounded-lg bg-orange-500/20 shrink-0">
              <AlertTriangle className="h-4 w-4 text-orange-400" />
            </div>
            <div>
              <p className="text-sm font-semibold text-orange-400">
                {summary!.pendingReview} asset{summary!.pendingReview !== 1 ? "s" : ""} require triage
              </p>
              <p className="text-xs text-muted-foreground">
                New shadow assets were discovered and need review — approve, remediate, or mark as false positive.
              </p>
            </div>
          </div>
          <Button
            size="sm"
            className="h-8 gap-1.5 bg-orange-500 hover:bg-orange-600 text-white shrink-0"
            onClick={() => setAssetStatus("new")}
          >
            <ShieldAlert className="h-3.5 w-3.5" /> Review Now
          </Button>
        </div>
      )}

      {/* ── Main Content: Sidebar + Table ────────────────────────────────────── */}
      <div className="flex flex-1 gap-0 min-h-0 overflow-hidden">

        {/* ── Left Filter Sidebar ─────────────────────────────────────────────── */}
        <div className="w-60 shrink-0 border-r border-border/40 overflow-y-auto bg-card/30 flex flex-col">
          <div className="p-4 space-y-5 flex-1">

            {/* Search */}
            <div>
              <p className="text-[10px] font-semibold text-muted-foreground uppercase tracking-wider mb-2">Search</p>
              <div className="relative">
                <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
                <Input
                  placeholder="Asset name…"
                  value={assetSearch}
                  onChange={e => setAssetSearch(e.target.value)}
                  className="pl-8 h-8 text-xs"
                />
              </div>
            </div>

            {/* Status filter */}
            <div>
              <p className="text-[10px] font-semibold text-muted-foreground uppercase tracking-wider mb-2">Status</p>
              <div className="space-y-1">
                {STATUS_FILTERS.map(f => (
                  <button
                    key={f.value}
                    onClick={() => { setAssetStatus(f.value); setAssetPage(0); }}
                    className={cn(
                      "w-full text-left px-2.5 py-1.5 rounded-lg text-xs font-medium transition-colors",
                      assetStatus === f.value
                        ? "bg-primary/15 text-primary border border-primary/30"
                        : "text-muted-foreground hover:bg-accent hover:text-foreground",
                    )}
                  >
                    {f.label}
                  </button>
                ))}
              </div>
            </div>

            {/* Risk filter */}
            <div>
              <p className="text-[10px] font-semibold text-muted-foreground uppercase tracking-wider mb-2">Risk Level</p>
              <div className="space-y-1">
                {[{ value: "", label: "All Risks" }, ...["critical","high","medium","low","info"].map(v => ({ value: v, label: RISK[v].label }))].map(f => (
                  <button
                    key={f.value}
                    onClick={() => { setAssetRisk(f.value); setAssetPage(0); }}
                    className={cn(
                      "w-full text-left px-2.5 py-1.5 rounded-lg text-xs font-medium transition-colors flex items-center gap-2",
                      assetRisk === f.value
                        ? "bg-primary/15 text-primary border border-primary/30"
                        : "text-muted-foreground hover:bg-accent hover:text-foreground",
                    )}
                  >
                    {f.value && <span className={cn("h-2 w-2 rounded-full shrink-0", RISK[f.value]?.dot)} />}
                    {f.label}
                    {f.value && summary?.byRisk[f.value] ? (
                      <span className="ml-auto text-[10px] tabular-nums opacity-60">{summary.byRisk[f.value]}</span>
                    ) : null}
                  </button>
                ))}
              </div>
            </div>

            {/* Asset type */}
            <div>
              <p className="text-[10px] font-semibold text-muted-foreground uppercase tracking-wider mb-2">Asset Type</p>
              <Select value={assetType || "_all"} onValueChange={v => { setAssetType(v === "_all" ? "" : v); setAssetPage(0); }}>
                <SelectTrigger className="h-8 text-xs">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="_all">All Types</SelectItem>
                  <SelectItem value="subdomain">Subdomain</SelectItem>
                  <SelectItem value="cloud_bucket">Cloud Bucket</SelectItem>
                  <SelectItem value="admin_panel">Admin Panel</SelectItem>
                  <SelectItem value="shadow_service">Shadow Service</SelectItem>
                  <SelectItem value="unauthorized_tech">Unauth Tech</SelectItem>
                  <SelectItem value="ip_asset">IP Asset</SelectItem>
                  <SelectItem value="email_service">Email Service</SelectItem>
                </SelectContent>
              </Select>
            </div>

            {/* Risk Distribution */}
            {summary && summary.totalAssets > 0 && (
              <div>
                <p className="text-[10px] font-semibold text-muted-foreground uppercase tracking-wider mb-2">
                  Risk Distribution
                </p>
                <div className="space-y-2">
                  {riskDistribution.filter(r => r.count > 0).map(r => (
                    <div key={r.level} className="space-y-1">
                      <div className="flex items-center justify-between text-[10px]">
                        <div className="flex items-center gap-1.5 text-muted-foreground">
                          <span className={cn("h-1.5 w-1.5 rounded-full", RISK[r.level].dot)} />
                          {RISK[r.level].label}
                        </div>
                        <span className="font-semibold tabular-nums text-foreground">{r.count}</span>
                      </div>
                      <div className="h-1 rounded-full bg-accent overflow-hidden">
                        <div className={cn("h-full rounded-full", RISK[r.level].bar)} style={{ width: `${r.pct}%` }} />
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Top Types */}
            {typeDistribution.length > 0 && (
              <div>
                <p className="text-[10px] font-semibold text-muted-foreground uppercase tracking-wider mb-2">
                  By Type
                </p>
                <div className="space-y-1.5">
                  {typeDistribution.map(({ type, count }) => (
                    <div key={type} className="flex items-center gap-2 text-xs">
                      <div className="shrink-0">{TYPE_ICONS[type] ?? <Layers className="w-3.5 h-3.5 text-slate-400" />}</div>
                      <span className="text-muted-foreground capitalize flex-1 truncate">{type.replace(/_/g, " ")}</span>
                      <span className="font-semibold tabular-nums text-foreground">{count}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Reset filters */}
          {(assetStatus || assetRisk || assetType || assetSearch) && (
            <div className="p-4 border-t border-border/40">
              <Button
                variant="ghost" size="sm"
                className="w-full h-7 text-xs text-muted-foreground hover:text-foreground gap-1"
                onClick={() => { setAssetStatus(""); setAssetRisk(""); setAssetType(""); setAssetSearch(""); setAssetPage(0); }}
              >
                <XCircle className="h-3 w-3" /> Clear Filters
              </Button>
            </div>
          )}
        </div>

        {/* ── Right Content Area ──────────────────────────────────────────────── */}
        <div className="flex-1 overflow-auto">
          <Tabs defaultValue="assets" className="flex flex-col h-full">

            {/* Tab bar */}
            <div className="border-b border-border/40 bg-card/20 px-4 pt-3 flex items-center justify-between gap-4">
              <TabsList className="h-9 bg-transparent gap-1 p-0">
                <TabsTrigger
                  value="assets"
                  className="h-8 px-4 data-[state=active]:bg-card data-[state=active]:border-b-2 data-[state=active]:border-primary data-[state=active]:shadow-none rounded-none border-b-2 border-transparent text-xs gap-1.5"
                >
                  <ShieldAlert className="h-3.5 w-3.5" />
                  Shadow Assets
                  {(summary?.pendingReview ?? 0) > 0 && (
                    <span className="ml-0.5 h-4 min-w-4 px-1 rounded-full bg-orange-500 text-white text-[9px] font-bold flex items-center justify-center">
                      {summary!.pendingReview}
                    </span>
                  )}
                </TabsTrigger>
                <TabsTrigger
                  value="saas"
                  className="h-8 px-4 data-[state=active]:bg-card data-[state=active]:border-b-2 data-[state=active]:border-primary data-[state=active]:shadow-none rounded-none border-b-2 border-transparent text-xs gap-1.5"
                >
                  <Cloud className="h-3.5 w-3.5" />
                  Shadow SaaS
                  {(summary?.totalSaasApps ?? 0) > 0 && (
                    <span className="ml-0.5 h-4 min-w-4 px-1 rounded-full bg-purple-500 text-white text-[9px] font-bold flex items-center justify-center">
                      {summary!.totalSaasApps}
                    </span>
                  )}
                </TabsTrigger>
              </TabsList>

              <div className="text-[10px] text-muted-foreground tabular-nums pb-2">
                {assetsData?.total ?? 0} assets · {saasData?.total ?? 0} SaaS apps
              </div>
            </div>

            {/* ── Assets Tab ──────────────────────────────────────────────────── */}
            <TabsContent value="assets" className="flex-1 m-0 overflow-auto">
              {assetsLoading ? (
                <div className="flex flex-col items-center justify-center py-32 gap-3">
                  <Loader2 className="h-7 w-7 animate-spin text-muted-foreground" />
                  <p className="text-sm text-muted-foreground">Loading assets…</p>
                </div>
              ) : assets.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-32 text-center gap-4">
                  <div className="p-5 rounded-2xl bg-accent/30 border border-border">
                    <Eye className="h-9 w-9 text-muted-foreground" />
                  </div>
                  <div>
                    <p className="font-semibold text-base">No shadow assets found</p>
                    <p className="text-sm text-muted-foreground mt-1.5 max-w-sm">
                      {assetSearch || assetStatus || assetRisk || assetType
                        ? "Try adjusting your filters to see more results."
                        : "Shadow IT assets are discovered automatically during pipeline scans."}
                    </p>
                  </div>
                  {canTriage && !assetSearch && !assetStatus && !assetRisk && !assetType && (
                    <Button variant="outline" size="sm" className="gap-1.5 mt-1" onClick={runScan} disabled={scanRunning}>
                      <Play className="h-3.5 w-3.5" /> Run Discovery Now
                    </Button>
                  )}
                  {(assetSearch || assetStatus || assetRisk || assetType) && (
                    <Button variant="outline" size="sm" className="gap-1.5 mt-1"
                      onClick={() => { setAssetStatus(""); setAssetRisk(""); setAssetType(""); setAssetSearch(""); setAssetPage(0); }}>
                      <XCircle className="h-3.5 w-3.5" /> Clear Filters
                    </Button>
                  )}
                </div>
              ) : (
                <>
                  <table className="w-full text-sm">
                    <thead className="sticky top-0 z-10 bg-card border-b border-border/60">
                      <tr>
                        <th className="pl-4 pr-2 py-2.5 w-8" />
                        <th className="py-2.5 pr-4 text-left text-[10px] font-semibold text-muted-foreground uppercase tracking-wider">Asset</th>
                        <th className="py-2.5 pr-4 text-left text-[10px] font-semibold text-muted-foreground uppercase tracking-wider">Type</th>
                        <th className="py-2.5 pr-4 text-left text-[10px] font-semibold text-muted-foreground uppercase tracking-wider">Class</th>
                        <th className="py-2.5 pr-6 text-left text-[10px] font-semibold text-muted-foreground uppercase tracking-wider min-w-[120px]">Risk Score</th>
                        <th className="py-2.5 pr-4 text-left text-[10px] font-semibold text-muted-foreground uppercase tracking-wider">Severity</th>
                        <th className="py-2.5 pr-4 text-left text-[10px] font-semibold text-muted-foreground uppercase tracking-wider">Status</th>
                        <th className="py-2.5 pr-4 text-left text-[10px] font-semibold text-muted-foreground uppercase tracking-wider hidden lg:table-cell">Flags</th>
                        <th className="py-2.5 pr-4 text-left text-[10px] font-semibold text-muted-foreground uppercase tracking-wider hidden xl:table-cell">First Seen</th>
                        <th className="py-2.5 pr-4 text-right text-[10px] font-semibold text-muted-foreground uppercase tracking-wider">Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {assets.map(asset => (
                        <AssetRow
                          key={asset.id}
                          asset={asset}
                          canTriage={canTriage}
                          onTriage={openTriage}
                          onEvidence={setEvidenceItem}
                        />
                      ))}
                    </tbody>
                  </table>

                  {/* Pagination */}
                  {totalPages > 1 && (
                    <div className="flex items-center justify-between text-xs px-4 py-3 border-t border-border/40 bg-card/20">
                      <span className="text-muted-foreground tabular-nums">
                        Page {assetPage + 1} of {totalPages} · {assetsData!.total} total
                      </span>
                      <div className="flex gap-2">
                        <Button variant="outline" size="sm" className="h-7 text-xs" disabled={assetPage === 0} onClick={() => setAssetPage(p => p - 1)}>
                          ← Previous
                        </Button>
                        <Button variant="outline" size="sm" className="h-7 text-xs" disabled={assetPage + 1 >= totalPages} onClick={() => setAssetPage(p => p + 1)}>
                          Next →
                        </Button>
                      </div>
                    </div>
                  )}
                </>
              )}
            </TabsContent>

            {/* ── SaaS Tab ────────────────────────────────────────────────────── */}
            <TabsContent value="saas" className="flex-1 m-0 overflow-auto">
              {/* SaaS filter bar */}
              <div className="sticky top-0 z-10 bg-card border-b border-border/40 px-4 py-2.5 flex items-center gap-3">
                <div className="relative flex-1 max-w-xs">
                  <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
                  <Input
                    placeholder="Search app name…"
                    value={saasSearch}
                    onChange={e => setSaasSearch(e.target.value)}
                    className="pl-8 h-8 text-xs"
                  />
                </div>
                <Select value={saasStatus || "_all"} onValueChange={v => setSaasStatus(v === "_all" ? "" : v)}>
                  <SelectTrigger className="w-36 h-8 text-xs">
                    <SelectValue placeholder="Status" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="_all">All Statuses</SelectItem>
                    <SelectItem value="new">New</SelectItem>
                    <SelectItem value="sanctioned">Sanctioned</SelectItem>
                    <SelectItem value="revoked">Revoked</SelectItem>
                  </SelectContent>
                </Select>
                <div className="flex items-center gap-2 ml-auto text-xs">
                  <div className="h-2 w-2 rounded-full bg-green-500" />
                  <span className="text-muted-foreground">{(saasData?.items ?? []).filter(a => a.isSanctioned).length} sanctioned</span>
                  <div className="h-2 w-2 rounded-full bg-orange-500 ml-2" />
                  <span className="text-muted-foreground">{(saasData?.items ?? []).filter(a => !a.isSanctioned).length} unsanctioned</span>
                </div>
              </div>

              {/* SaaS info banner */}
              <div className="mx-4 mt-3 mb-3 flex items-center gap-3 bg-purple-500/8 border border-purple-500/20 rounded-lg px-3 py-2.5">
                <div className="p-1.5 rounded-lg bg-purple-500/15 shrink-0">
                  <Mail className="h-3.5 w-3.5 text-purple-400" />
                </div>
                <p className="text-xs text-muted-foreground">
                  SaaS apps discovered via{" "}
                  <strong className="text-foreground">SPF records</strong>,{" "}
                  <strong className="text-foreground">DKIM selectors</strong>, and{" "}
                  <strong className="text-foreground">JavaScript API analysis</strong> during pipeline scans.
                </p>
              </div>

              {saasLoading ? (
                <div className="flex flex-col items-center justify-center py-32 gap-3">
                  <Loader2 className="h-7 w-7 animate-spin text-muted-foreground" />
                  <p className="text-sm text-muted-foreground">Loading SaaS apps…</p>
                </div>
              ) : saasApps.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-32 text-center gap-4">
                  <div className="p-5 rounded-2xl bg-accent/30 border border-border">
                    <Cloud className="h-9 w-9 text-muted-foreground" />
                  </div>
                  <div>
                    <p className="font-semibold text-base">No shadow SaaS apps found</p>
                    <p className="text-sm text-muted-foreground mt-1.5 max-w-sm">
                      SaaS apps are discovered from SPF includes and DKIM selectors during pipeline scans.
                    </p>
                  </div>
                </div>
              ) : (
                <table className="w-full text-sm">
                  <thead className="sticky top-0 z-10 bg-card border-b border-border/60">
                    <tr>
                      <th className="pl-4 pr-2 py-2.5 w-8" />
                      <th className="py-2.5 pr-4 text-left text-[10px] font-semibold text-muted-foreground uppercase tracking-wider">Application</th>
                      <th className="py-2.5 pr-4 text-left text-[10px] font-semibold text-muted-foreground uppercase tracking-wider">Source</th>
                      <th className="py-2.5 pr-4 text-left text-[10px] font-semibold text-muted-foreground uppercase tracking-wider">Risk</th>
                      <th className="py-2.5 pr-4 text-left text-[10px] font-semibold text-muted-foreground uppercase tracking-wider">Sanction</th>
                      <th className="py-2.5 pr-4 text-left text-[10px] font-semibold text-muted-foreground uppercase tracking-wider">Status</th>
                      <th className="py-2.5 pr-4 text-left text-[10px] font-semibold text-muted-foreground uppercase tracking-wider hidden xl:table-cell">Discovered</th>
                      <th className="py-2.5 pr-4 text-right text-[10px] font-semibold text-muted-foreground uppercase tracking-wider">Manage</th>
                    </tr>
                  </thead>
                  <tbody>
                    {saasApps.map(app => (
                      <SaasRow
                        key={app.id}
                        app={app}
                        canTriage={canTriage}
                        onSanction={(id, v) => saasMutation.mutate({ id, isSanctioned: v })}
                      />
                    ))}
                  </tbody>
                </table>
              )}
            </TabsContent>
          </Tabs>
        </div>
      </div>

      {/* ── Triage Dialog ────────────────────────────────────────────────────── */}
      <Dialog open={!!triageItem} onOpenChange={() => setTriageItem(null)}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-base">
              <div className="p-1.5 rounded-lg bg-orange-500/15">
                <ShieldAlert className="h-4 w-4 text-orange-400" />
              </div>
              Triage Shadow Asset
            </DialogTitle>
          </DialogHeader>
          {triageItem && (
            <div className="space-y-4 mt-1">
              {/* Asset info panel */}
              <div className="p-3.5 rounded-xl bg-accent/40 border border-border">
                <div className="flex items-start gap-2.5">
                  <div className="p-1.5 rounded-md bg-card shrink-0">
                    {TYPE_ICONS[triageItem.type] ?? <Layers className="w-4 h-4" />}
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="font-mono text-xs font-semibold break-all leading-snug">{triageItem.name}</p>
                    <p className="text-[10px] text-muted-foreground mt-0.5 capitalize">{triageItem.type.replace(/_/g, " ")} · {triageItem.source.replace(/_/g, " ")}</p>
                    <div className="flex flex-wrap gap-1 mt-2">
                      <ClassBadge cls={triageItem.classification} />
                      <RiskBadge level={triageItem.riskLevel} />
                      <StatusBadge status={triageItem.status} />
                    </div>
                  </div>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                {/* Severity override */}
                <div className="space-y-1.5">
                  <Label className="text-xs font-semibold">Severity Override</Label>
                  <Select value={triageRisk} onValueChange={setTriageRisk}>
                    <SelectTrigger className="h-9 text-xs">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {["critical","high","medium","low","info"].map(v => (
                        <SelectItem key={v} value={v}>
                          <span className="flex items-center gap-2">
                            <span className={cn("h-2 w-2 rounded-full", RISK[v].dot)} />
                            {RISK[v].label}
                          </span>
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>

                {/* Action */}
                <div className="space-y-1.5">
                  <Label className="text-xs font-semibold">Action</Label>
                  <Select value={triageStatus} onValueChange={setTriageStatus}>
                    <SelectTrigger className="h-9 text-xs">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="approved">✅ Approve</SelectItem>
                      <SelectItem value="remediated">🛠 Remediated</SelectItem>
                      <SelectItem value="under_review">🔍 Under Review</SelectItem>
                      <SelectItem value="false_positive">❌ False Positive</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>

              {/* Review Note */}
              <div className="space-y-1.5">
                <Label className="text-xs font-semibold">
                  Review Note <span className="text-muted-foreground font-normal">(optional)</span>
                </Label>
                <Textarea
                  className="text-sm resize-none"
                  placeholder="Add context about this decision…"
                  value={triageNote}
                  onChange={e => setTriageNote(e.target.value)}
                  rows={3}
                />
              </div>
            </div>
          )}
          <DialogFooter>
            <Button variant="outline" onClick={() => setTriageItem(null)}>Cancel</Button>
            <Button
              onClick={() => triageItem && triageMutation.mutate({
                id: triageItem.id,
                status: triageStatus,
                reviewNote: triageNote,
                riskLevel: triageRisk !== triageItem.riskLevel ? triageRisk : undefined,
              })}
              disabled={triageMutation.isPending}
            >
              {triageMutation.isPending && <Loader2 className="h-3.5 w-3.5 mr-1.5 animate-spin" />}
              Save Changes
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* ── Evidence Dialog ──────────────────────────────────────────────────── */}
      <Dialog open={!!evidenceItem} onOpenChange={() => setEvidenceItem(null)}>
        <DialogContent className="max-w-2xl max-h-[80vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-base">
              <div className="p-1.5 rounded-lg bg-blue-500/15">
                <FileText className="h-4 w-4 text-blue-400" />
              </div>
              Evidence — {evidenceItem?.name}
            </DialogTitle>
          </DialogHeader>
          {evidenceItem && (
            <div className="space-y-4 mt-1">
              {/* Details grid */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3 p-4 rounded-xl bg-accent/40 border border-border">
                {[
                  { label: "Type",           value: <span className="capitalize text-xs font-medium">{evidenceItem.type.replace(/_/g, " ")}</span> },
                  { label: "Source",         value: <span className="capitalize text-xs font-medium">{evidenceItem.source.replace(/_/g, " ")}</span> },
                  { label: "Classification", value: <ClassBadge cls={evidenceItem.classification} /> },
                  { label: "Risk",           value: <div className="flex items-center gap-1"><RiskBadge level={evidenceItem.riskLevel} />{evidenceItem.riskScore != null && <span className="text-xs text-muted-foreground">({Math.round(evidenceItem.riskScore)}/100)</span>}</div> },
                  { label: "First Seen",     value: <span className="text-xs font-medium">{fmtDate(evidenceItem.firstSeenAt)}</span> },
                  { label: "Last Seen",      value: <span className="text-xs font-medium">{fmtDate(evidenceItem.lastSeenAt)}</span> },
                  { label: "Status",         value: <StatusBadge status={evidenceItem.status} /> },
                  { label: "Cert Seen",      value: <span className="text-xs font-medium">{fmtDate(evidenceItem.certFirstSeen)}</span> },
                ].map(({ label, value }) => (
                  <div key={label}>
                    <p className="text-[9px] text-muted-foreground uppercase tracking-wide mb-1.5">{label}</p>
                    <div>{value}</div>
                  </div>
                ))}
              </div>

              {/* Security flags */}
              {(evidenceItem.hasOpenPorts || evidenceItem.hasAdminPanel || evidenceItem.hasAuthBypass || evidenceItem.isPubliclyAccessible) && (
                <div className="p-3.5 rounded-xl bg-red-500/5 border border-red-500/20">
                  <p className="text-[10px] text-muted-foreground uppercase tracking-wide mb-2 font-semibold">Security Flags</p>
                  <div className="flex flex-wrap gap-2">
                    {evidenceItem.hasOpenPorts        && <span className="flex items-center gap-1.5 text-xs bg-orange-500/10 text-orange-400 border border-orange-500/20 px-2.5 py-1 rounded-full"><Wifi className="h-3 w-3" /> Open Ports</span>}
                    {evidenceItem.hasAdminPanel       && <span className="flex items-center gap-1.5 text-xs bg-red-500/10 text-red-400 border border-red-500/20 px-2.5 py-1 rounded-full"><Terminal className="h-3 w-3" /> Admin Panel</span>}
                    {evidenceItem.hasAuthBypass       && <span className="flex items-center gap-1.5 text-xs bg-red-500/10 text-red-400 border border-red-500/20 px-2.5 py-1 rounded-full"><Lock className="h-3 w-3" /> No Authentication</span>}
                    {evidenceItem.isPubliclyAccessible && <span className="flex items-center gap-1.5 text-xs bg-blue-500/10 text-blue-400 border border-blue-500/20 px-2.5 py-1 rounded-full"><Globe className="h-3 w-3" /> Publicly Accessible</span>}
                  </div>
                </div>
              )}

              {/* Raw evidence */}
              {evidenceItem.evidence && Object.keys(evidenceItem.evidence).length > 0 && (
                <div>
                  <p className="text-[10px] text-muted-foreground uppercase tracking-wide mb-2.5 font-semibold">Raw Evidence Data</p>
                  <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
                    {Object.entries(evidenceItem.evidence).map(([k, v]) => (
                      <div key={k} className="bg-accent/30 border border-border rounded-lg px-3 py-2">
                        <p className="text-[9px] text-muted-foreground uppercase tracking-wide">{k.replace(/_/g, " ")}</p>
                        <p className="text-xs font-medium mt-0.5 break-all">
                          {typeof v === "boolean" ? (v ? "Yes" : "No")
                            : typeof v === "object" ? (
                              <span className="font-mono text-[10px]">{JSON.stringify(v).slice(0, 80)}</span>
                            ) : String(v ?? "—")}
                        </p>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Review note */}
              {evidenceItem.reviewNote && (
                <div className="p-3.5 rounded-xl bg-accent/30 border border-border">
                  <p className="text-[10px] text-muted-foreground uppercase tracking-wide mb-1.5 font-semibold">Review Note</p>
                  <p className="text-sm text-muted-foreground italic">"{evidenceItem.reviewNote}"</p>
                </div>
              )}
            </div>
          )}
          <DialogFooter>
            {canTriage && evidenceItem && (
              <Button variant="outline" size="sm" className="gap-1.5 mr-auto" onClick={() => { setEvidenceItem(null); openTriage(evidenceItem); }}>
                <ShieldAlert className="h-3.5 w-3.5" /> Triage This Asset
              </Button>
            )}
            <Button variant="outline" onClick={() => setEvidenceItem(null)}>Close</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
