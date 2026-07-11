import { useState, useEffect, useMemo } from "react";
import { useParams, useLocation } from "wouter";
import { useGetBrandThreatScan, getGetBrandThreatScanQueryKey, useDeleteBrandThreatScan, getListBrandThreatsQueryKey, useListBrandThreats } from "@workspace/api-client-react";
import { useQueryClient } from "@tanstack/react-query";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog";
import {
  ArrowLeft, Globe, AlertTriangle, CheckCircle2, XCircle,
  Loader2, Mail, Server, ChevronDown, ChevronUp, RefreshCw,
  ShieldAlert, Eye, Activity, Zap, Fingerprint, ExternalLink,
  Hash, Search, ChevronRight, Download, Fish, Database, Target,
  MapPin, Building2, Calendar, Shield, Info, Lock, Plus, Trash2,
  TrendingUp, Megaphone, History, BookmarkCheck, Clock, AtSign,
  Tag, Smartphone, RotateCw,
} from "lucide-react";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from "recharts";
import { Button } from "@/components/ui/button";
import { cn, formatDate } from "@/lib/utils";
import { downloadBrandThreatPdf, downloadBrandThreatCsv } from "@/lib/pdfReport";
import { getToken } from "@/lib/auth";
import { apiFetch } from "@/lib/apiFetch";
import { useToast } from "@/hooks/use-toast";

const RISK_META: Record<string, { label: string; color: string; bg: string; border: string; bar: string }> = {
  critical: { label: "Critical",  color: "text-red-400",    bg: "bg-red-500/10",    border: "border-red-500/30",    bar: "#f87171" },
  high:     { label: "High",      color: "text-orange-400", bg: "bg-orange-500/10", border: "border-orange-500/30", bar: "#fb923c" },
  medium:   { label: "Medium",    color: "text-yellow-400", bg: "bg-yellow-500/10", border: "border-yellow-500/30", bar: "#facc15" },
  low:      { label: "Low",       color: "text-green-400",  bg: "bg-green-500/10",  border: "border-green-500/30",  bar: "#4ade80" },
};

const SCORE_COLOR = (s: number) =>
  s >= 75 ? "#f87171" : s >= 50 ? "#fb923c" : s >= 25 ? "#facc15" : "#4ade80";

const FUZZER_META: Record<string, { label: string; color: string; bg: string; chartColor: string }> = {
  "omission":      { label: "Omission",     color: "text-blue-400",   bg: "bg-blue-500/10",   chartColor: "#60a5fa" },
  "repetition":    { label: "Repetition",   color: "text-purple-400", bg: "bg-purple-500/10", chartColor: "#c084fc" },
  "transposition": { label: "Transposition",color: "text-indigo-400", bg: "bg-indigo-500/10", chartColor: "#818cf8" },
  "replacement":   { label: "Keyboard Sub", color: "text-cyan-400",   bg: "bg-cyan-500/10",   chartColor: "#22d3ee" },
  "insertion":     { label: "Insertion",    color: "text-teal-400",   bg: "bg-teal-500/10",   chartColor: "#2dd4bf" },
  "vowel-swap":    { label: "Vowel Swap",   color: "text-sky-400",    bg: "bg-sky-500/10",    chartColor: "#38bdf8" },
  "hyphenation":   { label: "Hyphenation",  color: "text-violet-400", bg: "bg-violet-500/10", chartColor: "#a78bfa" },
  "homoglyph":     { label: "Homoglyph",    color: "text-rose-400",   bg: "bg-rose-500/10",   chartColor: "#fb7185" },
  "subdomain":     { label: "Subdomain",    color: "text-amber-400",  bg: "bg-amber-500/10",  chartColor: "#fbbf24" },
  "addition":      { label: "Addition",     color: "text-lime-400",   bg: "bg-lime-500/10",   chartColor: "#a3e635" },
  "tld-swap":      { label: "TLD Swap",     color: "text-pink-400",   bg: "bg-pink-500/10",   chartColor: "#f472b6" },
  "bitsquatting":  { label: "Bitsquatting", color: "text-orange-400", bg: "bg-orange-500/10", chartColor: "#fb923c" },
};

const ENGINE_META: Record<string, { color: string; bg: string; border: string }> = {
  "Shodan":       { color: "text-red-400",    bg: "bg-red-500/10",    border: "border-red-500/25" },
  "Censys":       { color: "text-blue-400",   bg: "bg-blue-500/10",   border: "border-blue-500/25" },
  "FOFA":         { color: "text-orange-400", bg: "bg-orange-500/10", border: "border-orange-500/25" },
  "Netlas":       { color: "text-teal-400",   bg: "bg-teal-500/10",   border: "border-teal-500/25" },
  "Hunter-How":   { color: "text-amber-400",  bg: "bg-amber-500/10",  border: "border-amber-500/25" },
  "Criminal IP":  { color: "text-rose-400",   bg: "bg-rose-500/10",   border: "border-rose-500/25" },
  "Zoomeye":      { color: "text-purple-400", bg: "bg-purple-500/10", border: "border-purple-500/25" },
  "Silent Push":  { color: "text-cyan-400",   bg: "bg-cyan-500/10",   border: "border-cyan-500/25" },
  "ODIN":         { color: "text-green-400",  bg: "bg-green-500/10",  border: "border-green-500/25" },
  "Validin":      { color: "text-violet-400", bg: "bg-violet-500/10", border: "border-violet-500/25" },
};

type FilterMode = "all" | "live" | "mx" | "suspicious" | "phishing";
type TabMode = "typosquatting" | "phishing" | "data_leaks" | "brand_abuse" | "malicious_ads" | "takedowns" | "favicon_clones" | "watchlist" | "subdomains";

function RiskScoreBar({ score }: { score: number }) {
  return (
    <div className="flex items-center gap-2 w-full">
      <div className="flex-1 h-1.5 bg-muted rounded-full overflow-hidden">
        <div className="h-full rounded-full transition-all" style={{ width: `${score}%`, backgroundColor: SCORE_COLOR(score) }} />
      </div>
      <span className="text-xs font-bold tabular-nums w-6 text-right" style={{ color: SCORE_COLOR(score) }}>
        {score}
      </span>
    </div>
  );
}

function HashChip({ label, value }: { label: string; value: string }) {
  const [copied, setCopied] = useState(false);
  function copy() {
    void navigator.clipboard.writeText(value);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }
  return (
    <button
      onClick={copy}
      title="Click to copy"
      className="flex flex-col gap-0.5 text-left group hover:bg-muted/60 rounded-lg px-2.5 py-2 transition-colors w-full"
    >
      <span className="text-[9px] uppercase tracking-widest text-muted-foreground font-semibold">{label}</span>
      <span className="font-mono text-[11px] text-foreground/80 break-all leading-snug group-hover:text-foreground transition-colors">
        {copied ? <span className="text-green-400">Copied!</span> : value}
      </span>
    </button>
  );
}

function FaviconIntelPanel({ scan }: { scan: any }) {
  const [collapsed, setCollapsed] = useState(false);
  const status: string = scan.favihunterStatus ?? "pending";
  const searchUrls: Record<string, { url: string; hash_type: string }> = scan.faviconSearchUrls ?? {};

  if (status === "pending" || status === "running") {
    return (
      <div className="bg-violet-500/5 border border-violet-500/20 rounded-xl p-4 flex items-center gap-3">
        <Loader2 className="w-4 h-4 animate-spin text-violet-400 shrink-0" />
        <div>
          <p className="text-sm font-medium text-violet-400">Favicon intelligence scan in progress</p>
          <p className="text-xs text-muted-foreground">favihunter is computing favicon hashes and generating search engine pivot URLs…</p>
        </div>
      </div>
    );
  }
  if (status === "skipped" || status === "error" || !scan.faviconMd5) {
    return (
      <div className="bg-muted/30 border border-border rounded-xl p-4 flex items-center gap-3">
        <Fingerprint className="w-4 h-4 text-muted-foreground/40 shrink-0" />
        <p className="text-xs text-muted-foreground">
          {status === "error"
            ? `Favicon intelligence unavailable: ${scan.favihunterError ?? "unknown error"}`
            : "No favicon found for this domain — skipping favicon intelligence."}
        </p>
      </div>
    );
  }

  const engines = Object.entries(searchUrls).filter(([k]) => k !== "_error");

  return (
    <div className="border border-violet-500/20 rounded-xl overflow-hidden bg-violet-500/3">
      <button className="w-full flex items-center gap-3 px-5 py-3.5 hover:bg-violet-500/5 transition-colors" onClick={() => setCollapsed(c => !c)}>
        <Fingerprint className="w-4 h-4 text-violet-400 shrink-0" />
        <span className="text-sm font-semibold text-violet-300">Favicon Intelligence</span>
        <span className="text-[10px] text-violet-400/60 bg-violet-500/10 border border-violet-500/20 px-1.5 py-0.5 rounded-full font-mono ml-1">
          powered by favihunter
        </span>
        <div className="flex-1" />
        <span className="text-xs text-muted-foreground mr-1">{engines.length} search engines</span>
        {collapsed ? <ChevronRight className="w-3.5 h-3.5 text-muted-foreground" /> : <ChevronDown className="w-3.5 h-3.5 text-muted-foreground" />}
      </button>
      {!collapsed && (
        <div className="border-t border-violet-500/15 px-5 py-4">
          <div className="flex gap-6 flex-wrap">
            <div className="flex flex-col items-center gap-2 shrink-0">
              <div className="w-12 h-12 rounded-xl border border-border bg-background flex items-center justify-center overflow-hidden">
                <img src={scan.faviconUrl} alt="favicon" className="w-10 h-10 object-contain" onError={e => { (e.target as HTMLImageElement).style.display = "none"; }} />
              </div>
              <p className="text-[9px] text-muted-foreground text-center max-w-[60px] break-all leading-tight font-mono">favicon.ico</p>
            </div>
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-1.5 mb-2">
                <Hash className="w-3 h-3 text-muted-foreground" />
                <span className="text-[10px] text-muted-foreground uppercase tracking-wider font-semibold">Favicon Hashes</span>
                <span className="text-[9px] text-muted-foreground/50">(click to copy)</span>
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-0.5">
                <HashChip label="MMH3 (Shodan / FOFA)" value={String(scan.faviconMmh3)} />
                <HashChip label="MMH3-HEX (Criminal IP)" value={scan.faviconMmh3Hex} />
                <HashChip label="MD5 (Censys / Hunter-How / ODIN / Validin)" value={scan.faviconMd5} />
                <HashChip label="SHA256 (Netlas)" value={scan.faviconSha256} />
              </div>
            </div>
          </div>
          {engines.length > 0 && (
            <div className="mt-4">
              <div className="flex items-center gap-1.5 mb-2">
                <Search className="w-3 h-3 text-muted-foreground" />
                <span className="text-[10px] text-muted-foreground uppercase tracking-wider font-semibold">Search Engine Pivots</span>
                <span className="text-[9px] text-muted-foreground/50 ml-1">— click to find hosts using the same favicon</span>
              </div>
              <div className="flex flex-wrap gap-2">
                {engines.map(([name, { url, hash_type }]) => {
                  const meta = ENGINE_META[name] ?? { color: "text-muted-foreground", bg: "bg-muted/50", border: "border-border" };
                  return (
                    <a key={name} href={url} target="_blank" rel="noopener noreferrer"
                      className={cn("flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs font-medium transition-all hover:scale-105 hover:shadow-sm", meta.color, meta.bg, meta.border)}
                      title={`Search ${name} using ${hash_type} hash`}
                    >
                      {name} <ExternalLink className="w-3 h-3 opacity-60" />
                    </a>
                  );
                })}
              </div>
              <p className="text-[10px] text-muted-foreground/40 mt-2">
                These links pivot on the domain's actual favicon fingerprint to find clones, phishing infrastructure, or related assets.
              </p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function ShodanFaviconPanel({ matches }: { matches: any[] }) {
  const [collapsed, setCollapsed] = useState(true);
  if (!matches || matches.length === 0) return null;
  return (
    <div className="border border-red-500/20 rounded-xl overflow-hidden bg-red-500/3 mt-3">
      <button className="w-full flex items-center gap-3 px-5 py-3.5 hover:bg-red-500/5 transition-colors" onClick={() => setCollapsed(c => !c)}>
        <Search className="w-4 h-4 text-red-400 shrink-0" />
        <span className="text-sm font-semibold text-red-300">Shodan Favicon Clone Hosts</span>
        <span className="ml-1 text-[10px] font-bold bg-red-500/10 border border-red-500/20 text-red-400 px-2 py-0.5 rounded-full">
          {matches.length} host{matches.length !== 1 ? "s" : ""} detected
        </span>
        <div className="flex-1" />
        <span className="text-[10px] text-muted-foreground mr-1">Hosts sharing the same favicon fingerprint</span>
        {collapsed ? <ChevronRight className="w-3.5 h-3.5 text-muted-foreground" /> : <ChevronDown className="w-3.5 h-3.5 text-muted-foreground" />}
      </button>
      {!collapsed && (
        <div className="border-t border-red-500/15 px-5 py-4 space-y-2">
          <p className="text-[10px] text-muted-foreground/60 mb-3">
            These IPs/hostnames were found by Shodan using the same favicon hash as your domain. They may be phishing infrastructure or brand clones.
          </p>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
            {matches.map((m: any, i: number) => (
              <div key={i} className="flex items-center gap-2 bg-background/60 border border-red-500/20 rounded-lg px-3 py-2">
                <Server className="w-3 h-3 text-red-400 shrink-0" />
                <div className="min-w-0 flex-1">
                  <p className="text-xs font-mono truncate">{m.ip_str ?? m.ip ?? m.hostname ?? "unknown"}</p>
                  {m.hostnames?.length > 0 && <p className="text-[10px] text-muted-foreground truncate">{m.hostnames[0]}</p>}
                  {(m.org || m.isp) && <p className="text-[10px] text-muted-foreground/60 truncate">{m.org ?? m.isp}</p>}
                </div>
                {m.country_code && (
                  <span className="text-[10px] font-bold text-muted-foreground bg-muted px-1.5 py-0.5 rounded-sm shrink-0">{m.country_code}</span>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function PhishingTab({ phishing }: { phishing: any[] }) {
  if (!phishing.length) {
    return (
      <div className="flex flex-col items-center justify-center py-24 text-center">
        <Shield className="w-10 h-10 text-green-400/40 mb-3" />
        <p className="text-base font-semibold text-green-400">No phishing domains detected</p>
        <p className="text-sm text-muted-foreground mt-1">
          PhishTank, OpenPhish, and Google Safe Browsing found no confirmed phishing domains in this scan.
        </p>
      </div>
    );
  }
  return (
    <div className="p-5 space-y-3">
      <div className="flex items-center gap-2 mb-4">
        <Fish className="w-4 h-4 text-red-400" />
        <span className="font-semibold">{phishing.length} confirmed phishing domain{phishing.length !== 1 ? "s" : ""}</span>
        <span className="text-xs text-muted-foreground">— live confirmed phishing infrastructure</span>
      </div>
      {phishing.map((p: any) => (
        <div key={p.id} className="bg-card border border-red-500/20 rounded-xl p-4 space-y-2">
          <div className="flex items-start justify-between gap-2">
            <div className="flex items-center gap-2 min-w-0">
              <Fish className="w-3.5 h-3.5 text-red-400 shrink-0" />
              <span className="font-mono text-sm text-red-300 truncate">{p.url}</span>
            </div>
            <span className="text-[10px] bg-red-500/10 text-red-400 border border-red-500/20 px-2 py-0.5 rounded-full font-semibold shrink-0">
              {p.source}
            </span>
          </div>
          <div className="flex items-center gap-4 text-xs text-muted-foreground flex-wrap">
            {p.targetBrand && <span><span className="font-medium text-foreground/70">Target:</span> {p.targetBrand}</span>}
            {p.threatType && <span><span className="font-medium text-foreground/70">Type:</span> {p.threatType.replace(/_/g, " ")}</span>}
            {p.submittedAt && <span><span className="font-medium text-foreground/70">Detected:</span> {formatDate(p.submittedAt)}</span>}
            {p.verified && <span className="text-green-400 flex items-center gap-0.5"><CheckCircle2 className="w-3 h-3" /> Verified</span>}
          </div>
          <div className="flex items-center gap-2">
            <a href={`https://www.virustotal.com/gui/url/${btoa(p.url)}`} target="_blank" rel="noopener noreferrer"
              className="text-[11px] text-muted-foreground hover:text-foreground transition-colors flex items-center gap-1">
              <ExternalLink className="w-3 h-3" /> VirusTotal
            </a>
            <a href={`https://phishtank.org/phish_search.php?valid=y&active=y&Search=Search&q=${encodeURIComponent(p.url)}`} target="_blank" rel="noopener noreferrer"
              className="text-[11px] text-muted-foreground hover:text-foreground transition-colors flex items-center gap-1">
              <ExternalLink className="w-3 h-3" /> PhishTank
            </a>
          </div>
        </div>
      ))}
    </div>
  );
}

function DataLeaksTab({ leaks }: { leaks: any[] }) {
  if (!leaks.length) {
    return (
      <div className="flex flex-col items-center justify-center py-24 text-center">
        <Shield className="w-10 h-10 text-green-400/40 mb-3" />
        <p className="text-base font-semibold text-green-400">No data breaches found</p>
        <p className="text-sm text-muted-foreground mt-1">
          HIBP (Have I Been Pwned) found no known data breaches associated with this domain.
        </p>
      </div>
    );
  }
  const SEV_META: Record<string, { color: string; bg: string; border: string }> = {
    critical: { color: "text-red-400", bg: "bg-red-500/10", border: "border-red-500/20" },
    high:     { color: "text-orange-400", bg: "bg-orange-500/10", border: "border-orange-500/20" },
    medium:   { color: "text-yellow-400", bg: "bg-yellow-500/10", border: "border-yellow-500/20" },
    low:      { color: "text-green-400", bg: "bg-green-500/10", border: "border-green-500/20" },
  };
  return (
    <div className="p-5 space-y-4">
      <div className="flex items-center gap-2 mb-4">
        <Database className="w-4 h-4 text-orange-400" />
        <span className="font-semibold">{leaks.length} data breach record{leaks.length !== 1 ? "s" : ""}</span>
        <span className="text-xs text-muted-foreground">— sourced from HIBP (Have I Been Pwned)</span>
      </div>
      {leaks.map((leak: any) => {
        const sev = SEV_META[leak.severity] ?? SEV_META.low;
        const dataClasses: string[] = Array.isArray(leak.exposedData) ? leak.exposedData : [];
        return (
          <div key={leak.id} className={cn("bg-card border rounded-xl p-4 space-y-3", sev.border)}>
            <div className="flex items-start justify-between gap-2">
              <div>
                <div className="flex items-center gap-2">
                  <Database className="w-3.5 h-3.5 text-orange-400 shrink-0" />
                  <span className="font-semibold text-sm">{leak.title}</span>
                  <span className={cn("text-[10px] px-2 py-0.5 rounded-full border font-semibold capitalize", sev.color, sev.bg, sev.border)}>
                    {leak.severity}
                  </span>
                </div>
                {leak.domainMatch && (
                  <p className="text-[11px] text-muted-foreground mt-0.5 ml-5">Domain: {leak.domainMatch}</p>
                )}
              </div>
              {leak.breachDate && (
                <span className="text-[11px] text-muted-foreground flex items-center gap-1 shrink-0">
                  <Calendar className="w-3 h-3" /> {leak.breachDate}
                </span>
              )}
            </div>
            {leak.description && (
              <p className="text-xs text-muted-foreground/80 leading-relaxed ml-5">{leak.description}</p>
            )}
            {dataClasses.length > 0 && (
              <div className="ml-5">
                <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-2">Exposed Data Classes</p>
                <div className="flex flex-wrap gap-1.5">
                  {dataClasses.map((dc: string) => (
                    <span key={dc} className="text-[10px] bg-muted/50 border border-border px-2 py-0.5 rounded-full text-foreground/70">
                      {dc}
                    </span>
                  ))}
                </div>
              </div>
            )}
            {leak.url && (
              <div className="ml-5">
                <a href={leak.url} target="_blank" rel="noopener noreferrer"
                  className="text-[11px] text-muted-foreground hover:text-foreground transition-colors flex items-center gap-1 w-fit">
                  <ExternalLink className="w-3 h-3" /> View on HIBP
                </a>
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

const PLATFORM_META: Record<string, { color: string; bg: string; border: string }> = {
  "Google Play Store":      { color: "text-green-400",   bg: "bg-green-500/10",   border: "border-green-500/25" },
  "Apple App Store":        { color: "text-blue-400",    bg: "bg-blue-500/10",    border: "border-blue-500/25" },
  "APKPure":                { color: "text-orange-400",  bg: "bg-orange-500/10",  border: "border-orange-500/25" },
  "Aptoide":                { color: "text-purple-400",  bg: "bg-purple-500/10",  border: "border-purple-500/25" },
  "Samsung Galaxy Store":   { color: "text-teal-400",    bg: "bg-teal-500/10",    border: "border-teal-500/25" },
  "Huawei AppGallery":      { color: "text-red-400",     bg: "bg-red-500/10",     border: "border-red-500/25" },
  "Amazon Appstore":        { color: "text-yellow-400",  bg: "bg-yellow-500/10",  border: "border-yellow-500/25" },
  "Cydia/Sileo (Chariz)":   { color: "text-slate-400",   bg: "bg-slate-500/10",   border: "border-slate-500/25" },
  "Cydia/Sileo (Havoc)":    { color: "text-slate-400",   bg: "bg-slate-500/10",   border: "border-slate-500/25" },
  "Cydia/Sileo (BigBoss)":  { color: "text-slate-400",   bg: "bg-slate-500/10",   border: "border-slate-500/25" },
  "Cydia/Sileo":            { color: "text-slate-400",   bg: "bg-slate-500/10",   border: "border-slate-500/25" },
  "Certificate Transparency": { color: "text-violet-400", bg: "bg-violet-500/10", border: "border-violet-500/25" },
  "DNS":                    { color: "text-blue-400",    bg: "bg-blue-500/10",    border: "border-blue-500/25" },
  "YouTube":                { color: "text-red-400",     bg: "bg-red-500/10",     border: "border-red-500/25" },
  "Reddit":                 { color: "text-orange-400",  bg: "bg-orange-500/10",  border: "border-orange-500/25" },
  "Twitter/X":              { color: "text-slate-400",   bg: "bg-slate-500/10",   border: "border-slate-500/25" },
  "Instagram":              { color: "text-pink-400",    bg: "bg-pink-500/10",    border: "border-pink-500/25" },
  "Facebook":               { color: "text-blue-400",    bg: "bg-blue-500/10",    border: "border-blue-500/25" },
  "TikTok":                 { color: "text-cyan-400",    bg: "bg-cyan-500/10",    border: "border-cyan-500/25" },
};

const APP_STORE_PLATFORMS = new Set([
  "Google Play Store", "Apple App Store", "APKPure", "Aptoide",
  "Samsung Galaxy Store", "Huawei AppGallery", "Amazon Appstore",
  "Cydia/Sileo (Chariz)", "Cydia/Sileo (Havoc)", "Cydia/Sileo (BigBoss)", "Cydia/Sileo",
]);

function PlatformBadge({ platform }: { platform: string }) {
  const meta = PLATFORM_META[platform] ?? { color: "text-muted-foreground", bg: "bg-muted/50", border: "border-border" };
  return (
    <span className={cn("text-[10px] px-2 py-0.5 rounded-full border font-medium shrink-0", meta.color, meta.bg, meta.border)}>
      {platform}
    </span>
  );
}

interface SocialSourceStatus {
  twitter_x: boolean;
  instagram: boolean;
  tiktok: boolean;
  youtube: boolean;
  meta_ads: boolean;
}

const SOCIAL_SOURCES: { key: keyof SocialSourceStatus; label: string; settingsPath: string }[] = [
  { key: "twitter_x", label: "Twitter/X", settingsPath: "/settings/platform" },
  { key: "instagram", label: "Instagram",  settingsPath: "/settings/platform" },
  { key: "tiktok",   label: "TikTok",     settingsPath: "/settings/platform" },
  { key: "youtube",  label: "YouTube",    settingsPath: "/settings/platform" },
  { key: "meta_ads", label: "Meta Ads",   settingsPath: "/settings/platform" },
];

const BASE_URL = import.meta.env.BASE_URL.replace(/\/$/, "");

function SocialSourceBadges() {
  const [status, setStatus] = useState<SocialSourceStatus | null>(null);

  useEffect(() => {
    apiFetch<SocialSourceStatus>(`${BASE_URL}/api/platform/social-source-status`)
      .then(data => setStatus(data))
      .catch(() => {});
  }, []);

  if (!status) return null;

  return (
    <div className="flex items-center gap-1.5 flex-wrap">
      {SOCIAL_SOURCES.map(({ key, label, settingsPath }) =>
        status[key] ? (
          <span
            key={key}
            className="inline-flex items-center gap-1 text-[10px] font-semibold px-2 py-0.5 rounded-full border bg-emerald-500/10 border-emerald-500/25 text-emerald-400"
          >
            <CheckCircle2 className="w-2.5 h-2.5" />
            {label}
          </span>
        ) : (
          <a
            key={key}
            href={settingsPath}
            className="inline-flex items-center gap-1 text-[10px] font-medium px-2 py-0.5 rounded-full border bg-muted/40 border-border text-muted-foreground hover:text-foreground hover:border-muted-foreground/40 transition-colors"
            title={`${label} API key not configured — click to set up`}
          >
            <XCircle className="w-2.5 h-2.5" />
            {label}
          </a>
        )
      )}
    </div>
  );
}

interface ScanWarning {
  platform: string;
  code: string;
  message: string;
  timestamp: string;
}

const SOCIAL_PLATFORM_LINKS: { name: string; searchUrl: (brand: string) => string; color: string; bg: string; border: string }[] = [
  {
    name: "Twitter/X",
    searchUrl: (b) => `https://twitter.com/search?q=%22${encodeURIComponent(b)}%22&f=user`,
    color: "text-slate-300", bg: "bg-slate-500/10", border: "border-slate-500/25",
  },
  {
    name: "Instagram",
    searchUrl: (b) => `https://www.instagram.com/explore/search/?q=${encodeURIComponent(b)}`,
    color: "text-pink-400", bg: "bg-pink-500/10", border: "border-pink-500/25",
  },
  {
    name: "TikTok",
    searchUrl: (b) => `https://www.tiktok.com/search/user?q=${encodeURIComponent(b)}`,
    color: "text-cyan-400", bg: "bg-cyan-500/10", border: "border-cyan-500/25",
  },
  {
    name: "Facebook",
    searchUrl: (b) => `https://www.facebook.com/search/pages?q=${encodeURIComponent(b)}`,
    color: "text-blue-400", bg: "bg-blue-500/10", border: "border-blue-500/25",
  },
  {
    name: "YouTube",
    searchUrl: (b) => `https://www.youtube.com/results?search_query=${encodeURIComponent(b)}+official&sp=EgIQAg%3D%3D`,
    color: "text-red-400", bg: "bg-red-500/10", border: "border-red-500/25",
  },
  {
    name: "LinkedIn",
    searchUrl: (b) => `https://www.linkedin.com/search/results/companies/?keywords=${encodeURIComponent(b)}`,
    color: "text-sky-400", bg: "bg-sky-500/10", border: "border-sky-500/25",
  },
];

function SubdomainsTab({ subdomains, pipelineScanId, scanDomain }: { subdomains: string[]; pipelineScanId: number; scanDomain: string }) {
  const [search, setSearch] = useState("");
  const filtered = search.trim()
    ? subdomains.filter(s => s.includes(search.trim().toLowerCase()))
    : subdomains;

  return (
    <div className="p-6 space-y-5">
      {/* Header card */}
      <div className="flex items-start gap-4 p-5 bg-blue-500/5 border border-blue-500/20 rounded-xl">
        <div className="w-10 h-10 rounded-xl bg-blue-500/10 border border-blue-500/20 flex items-center justify-center shrink-0">
          <Server className="w-5 h-5 text-blue-400" />
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <span className="text-sm font-semibold">Discovered Subdomains</span>
            <span className="text-[10px] font-mono text-blue-400/70 bg-blue-500/10 border border-blue-500/20 px-1.5 py-0.5 rounded-full">
              pipeline scan #{pipelineScanId}
            </span>
          </div>
          <p className="text-xs text-muted-foreground">
            {subdomains.length} subdomain{subdomains.length !== 1 ? "s" : ""} enumerated for <span className="font-mono text-foreground">{scanDomain}</span> during the linked asset scan.
            Review for shadow IT, forgotten services, exposed dev environments, or subdomain takeover candidates.
          </p>
        </div>
        <div className="text-right shrink-0">
          <p className="text-2xl font-bold text-blue-400">{subdomains.length}</p>
          <p className="text-[10px] text-muted-foreground">subdomains</p>
        </div>
      </div>

      {/* Search */}
      <div className="relative">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
        <input
          type="text"
          value={search}
          onChange={e => setSearch(e.target.value)}
          placeholder="Filter subdomains…"
          className="w-full pl-8 pr-3 py-2 text-sm bg-background border border-border rounded-xl focus:outline-none focus:ring-1 focus:ring-primary/40"
        />
        {search && (
          <button onClick={() => setSearch("")} className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground">
            ✕
          </button>
        )}
      </div>

      {/* Results count */}
      {search && (
        <p className="text-xs text-muted-foreground">
          Showing {filtered.length} of {subdomains.length} subdomains matching <span className="font-mono text-foreground">"{search}"</span>
        </p>
      )}

      {/* Subdomain grid */}
      {filtered.length > 0 ? (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
          {filtered.map(sub => {
            const isApex = sub === scanDomain || sub === `www.${scanDomain}`;
            const label = sub.replace(`.${scanDomain}`, "");
            return (
              <div
                key={sub}
                className={cn(
                  "flex items-center gap-2.5 px-3.5 py-2.5 rounded-xl border text-sm transition-all group",
                  isApex
                    ? "bg-blue-500/10 border-blue-500/25"
                    : "bg-background border-border hover:border-blue-500/30 hover:bg-blue-500/5",
                )}
              >
                <Globe className={cn("w-3.5 h-3.5 shrink-0", isApex ? "text-blue-400" : "text-muted-foreground group-hover:text-blue-400")} />
                <div className="flex-1 min-w-0">
                  <span className="font-mono text-xs truncate block">{sub}</span>
                  {!isApex && label !== sub && (
                    <span className="text-[10px] text-muted-foreground">.{scanDomain}</span>
                  )}
                </div>
                <a
                  href={`https://${sub}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="opacity-0 group-hover:opacity-100 transition-opacity text-muted-foreground hover:text-foreground"
                  title={`Open https://${sub}`}
                >
                  <ExternalLink className="w-3 h-3" />
                </a>
              </div>
            );
          })}
        </div>
      ) : (
        <div className="flex flex-col items-center justify-center py-16 gap-3 text-center">
          <Server className="w-10 h-10 text-muted-foreground/20" />
          <p className="text-sm text-muted-foreground">No subdomains match <span className="font-mono">"{search}"</span></p>
          <button onClick={() => setSearch("")} className="text-xs text-primary hover:underline">Clear filter</button>
        </div>
      )}

      {/* Risk advisory */}
      <div className="border border-amber-500/20 bg-amber-500/5 rounded-xl p-4 space-y-1.5">
        <div className="flex items-center gap-2">
          <AlertTriangle className="w-3.5 h-3.5 text-amber-400 shrink-0" />
          <p className="text-xs font-semibold text-amber-300">Subdomain Takeover Advisory</p>
        </div>
        <p className="text-xs text-muted-foreground ml-5.5">
          Subdomains pointing to decommissioned services (dangling DNS) may be vulnerable to takeover.
          Cross-reference with your asset inventory and verify each subdomain has an active, controlled backend.
          Run a dedicated scan on any subdomain that appears in your asset list but is not actively monitored.
        </p>
      </div>
    </div>
  );
}


function SocialPlatformMonitor({ scanDomain }: { scanDomain?: string }) {
  const brand = scanDomain?.replace(/\.[^.]+$/, "") ?? "brand";
  return (
    <div className="border border-border rounded-xl p-5 bg-muted/10 space-y-4">
      <div className="flex items-start gap-3">
        <AtSign className="w-4 h-4 text-pink-400 shrink-0 mt-0.5" />
        <div className="flex-1 min-w-0">
          <p className="text-sm font-semibold">Social Media Monitor</p>
          <p className="text-xs text-muted-foreground mt-0.5">
            Automated social platform scanning requires API tokens. Use the links below to manually investigate each platform for impersonating accounts or pages.
          </p>
        </div>
        <a href="/settings/platform" className="text-[10px] text-primary hover:text-primary/80 shrink-0 flex items-center gap-1">
          Configure APIs <ExternalLink className="w-2.5 h-2.5" />
        </a>
      </div>
      <div className="flex flex-wrap gap-2">
        {SOCIAL_PLATFORM_LINKS.map(p => (
          <a
            key={p.name}
            href={p.searchUrl(brand)}
            target="_blank"
            rel="noopener noreferrer"
            className={cn(
              "flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs font-medium transition-all hover:scale-105",
              p.color, p.bg, p.border,
            )}
          >
            {p.name} <ExternalLink className="w-3 h-3 opacity-60" />
          </a>
        ))}
      </div>
      <p className="text-[10px] text-muted-foreground/50">
        Search for <span className="font-mono text-muted-foreground">"{brand}"</span> on each platform to find impersonating accounts, squatted pages, or brand-abuse content.
        To enable automated scanning, configure Twitter/X Bearer Token, Instagram Graph Token, TikTok Research Token, or YouTube API Key in{" "}
        <a href="/settings/platform" className="text-primary hover:underline">Platform Settings → Brand Intelligence</a>.
      </p>
    </div>
  );
}

function BrandAbuseTab({ abuse, warnings, scanDomain }: { abuse: any[]; warnings?: ScanWarning[]; scanDomain?: string }) {
  const activeWarnings = warnings?.filter(w => w.code === "rate_limited") ?? [];
  const socialResults = abuse.filter(r => r.type === "fake_social");

  if (!abuse.length) {
    return (
      <div className="p-6 space-y-5">
        <div className="flex flex-col items-center justify-center py-16 text-center">
          <Shield className="w-10 h-10 text-green-400/40 mb-3" />
          <p className="text-base font-semibold text-green-400">No brand abuse found</p>
          <p className="text-sm text-muted-foreground mt-1">
            Certificate transparency, DNS lookalike, and app store checks found no brand abuse.
          </p>
          {activeWarnings.length > 0 && (
            <div className="mt-6 w-full max-w-lg text-left space-y-2">
              {activeWarnings.map((w, i) => (
                <div key={i} className="flex items-start gap-2.5 rounded-md border border-amber-500/30 bg-amber-500/10 px-3.5 py-2.5">
                  <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                  <div>
                    <p className="text-xs font-semibold text-amber-300">{w.platform} rate limited</p>
                    <p className="text-xs text-amber-200/80 mt-0.5">{w.message}</p>
                  </div>
                </div>
              ))}
            </div>
          )}
          <div className="mt-4">
            <SocialSourceBadges />
          </div>
        </div>
        <SocialPlatformMonitor scanDomain={scanDomain} />
      </div>
    );
  }

  const RISK_COLOR: Record<string, string> = {
    critical: "text-red-400 bg-red-500/10 border-red-500/20",
    high: "text-orange-400 bg-orange-500/10 border-orange-500/20",
    medium: "text-yellow-400 bg-yellow-500/10 border-yellow-500/20",
    low: "text-green-400 bg-green-500/10 border-green-500/20",
  };

  const TYPE_ICON: Record<string, React.ReactNode> = {
    suspicious_certificate: <Lock className="w-3.5 h-3.5 text-violet-400 shrink-0" />,
    lookalike_domain:       <Globe className="w-3.5 h-3.5 text-red-400 shrink-0" />,
    rogue_app:              <Target className="w-3.5 h-3.5 text-orange-400 shrink-0" />,
    fake_social:            <Target className="w-3.5 h-3.5 text-pink-400 shrink-0" />,
    brand_abuse:            <AlertTriangle className="w-3.5 h-3.5 text-yellow-400 shrink-0" />,
    impersonation:          <AlertTriangle className="w-3.5 h-3.5 text-red-400 shrink-0" />,
  };

  // Group rogue_app items by platform; group everything else by type
  const appStoreItems = abuse.filter(r => r.type === "rogue_app" && r.platform && APP_STORE_PLATFORMS.has(r.platform));
  const otherItems    = abuse.filter(r => !(r.type === "rogue_app" && r.platform && APP_STORE_PLATFORMS.has(r.platform)));

  const appsByPlatform = appStoreItems.reduce((acc: Record<string, any[]>, r: any) => {
    const key = r.platform ?? "Unknown Store";
    if (!acc[key]) acc[key] = [];
    acc[key]!.push(r);
    return acc;
  }, {});

  const otherByType = otherItems.reduce((acc: Record<string, any[]>, r: any) => {
    if (!acc[r.type]) acc[r.type] = [];
    acc[r.type]!.push(r);
    return acc;
  }, {});

  const PLATFORM_ORDER = [
    "Google Play Store", "Apple App Store", "APKPure", "Aptoide",
    "Samsung Galaxy Store", "Huawei AppGallery", "Amazon Appstore",
    "Cydia/Sileo (BigBoss)", "Cydia/Sileo (Chariz)", "Cydia/Sileo (Havoc)", "Cydia/Sileo",
  ];
  const sortedPlatforms = [
    ...PLATFORM_ORDER.filter(p => appsByPlatform[p]),
    ...Object.keys(appsByPlatform).filter(p => !PLATFORM_ORDER.includes(p)),
  ];

  return (
    <div className="p-5 space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3 mb-2">
        <div className="flex items-center gap-2">
          <Target className="w-4 h-4 text-orange-400" />
          <span className="font-semibold">{abuse.length} brand abuse finding{abuse.length !== 1 ? "s" : ""}</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-[10px] text-muted-foreground uppercase tracking-wider font-medium">Live sources:</span>
          <SocialSourceBadges />
        </div>
      </div>

      {/* Rate-limit warnings */}
      {activeWarnings.length > 0 && (
        <div className="space-y-2">
          {activeWarnings.map((w, i) => (
            <div key={i} className="flex items-start gap-2.5 rounded-md border border-amber-500/30 bg-amber-500/10 px-3.5 py-2.5">
              <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
              <div>
                <p className="text-xs font-semibold text-amber-300">{w.platform} rate limited — results may be incomplete</p>
                <p className="text-xs text-amber-200/80 mt-0.5">{w.message}</p>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* App Store section — per-platform grouping */}
      {sortedPlatforms.length > 0 && (
        <div className="space-y-5">
          <div className="flex items-center gap-2">
            <Target className="w-3.5 h-3.5 text-orange-400 shrink-0" />
            <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
              Rogue Apps — App Stores ({appStoreItems.length})
            </p>
          </div>
          {sortedPlatforms.map(platform => {
            const items: any[] = appsByPlatform[platform] ?? [];
            const pmeta = PLATFORM_META[platform] ?? { color: "text-muted-foreground", bg: "bg-muted/50", border: "border-border" };
            return (
              <div key={platform}>
                <div className={cn("flex items-center gap-2 mb-2 px-3 py-1.5 rounded-lg border w-fit", pmeta.bg, pmeta.border)}>
                  <span className={cn("text-[11px] font-semibold", pmeta.color)}>{platform}</span>
                  <span className={cn("text-[10px] opacity-60", pmeta.color)}>({items.length})</span>
                </div>
                <div className="space-y-2">
                  {items.map((item: any) => (
                    <div key={item.id} className="bg-card border border-border rounded-xl p-3.5">
                      <div className="flex items-start gap-3">
                        {/* App icon */}
                        {item.iconUrl ? (
                          <img
                            src={item.iconUrl}
                            alt=""
                            className="w-10 h-10 rounded-xl border border-border object-cover shrink-0 mt-0.5"
                            onError={e => { (e.target as HTMLImageElement).style.display = "none"; }}
                          />
                        ) : (
                          <div className="w-10 h-10 rounded-xl border border-border bg-muted/30 flex items-center justify-center shrink-0 mt-0.5">
                            <Target className="w-4 h-4 text-muted-foreground/40" />
                          </div>
                        )}
                        <div className="flex-1 min-w-0">
                          <div className="flex items-start justify-between gap-2 mb-1">
                            <span className="text-sm font-medium leading-snug">
                              {item.title ?? item.url ?? item.platform}
                            </span>
                            <span className={cn("text-[10px] px-2 py-0.5 rounded-full border font-semibold capitalize shrink-0", RISK_COLOR[item.risk] ?? RISK_COLOR.medium)}>
                              {item.risk}
                            </span>
                          </div>
                          {item.description && (
                            <p className="text-xs text-muted-foreground/80 leading-relaxed">{item.description}</p>
                          )}
                          <div className="flex items-center gap-3 mt-1.5 flex-wrap">
                            {item.installCount && (
                              <span className="text-[11px] text-muted-foreground flex items-center gap-1">
                                <TrendingUp className="w-3 h-3" /> {item.installCount}
                              </span>
                            )}
                            {item.evidenceSnippet && (
                              <span className="text-[11px] font-mono text-muted-foreground/60 truncate max-w-xs">
                                {item.evidenceSnippet}
                              </span>
                            )}
                          </div>
                          {item.url && (
                            <a href={item.url} target="_blank" rel="noopener noreferrer"
                              className="mt-1.5 text-[11px] text-muted-foreground hover:text-foreground transition-colors flex items-center gap-1 w-fit">
                              <ExternalLink className="w-3 h-3" /> {item.url.slice(0, 55)}{item.url.length > 55 ? "…" : ""}
                            </a>
                          )}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Other findings — grouped by type */}
      {Object.entries(otherByType).map(([type, items]) => (
        <div key={type}>
          <div className="flex items-center gap-2 mb-3">
            {TYPE_ICON[type] ?? <AlertTriangle className="w-3.5 h-3.5 text-muted-foreground shrink-0" />}
            <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
              {type.replace(/_/g, " ")} ({(items as any[]).length})
            </p>
          </div>
          <div className="space-y-2">
            {(items as any[]).map((item: any) => (
              <div key={item.id} className="bg-card border border-border rounded-xl p-4">
                <div className="flex items-start justify-between gap-2 mb-2">
                  <div className="flex items-center gap-2 min-w-0">
                    {TYPE_ICON[item.type] ?? <AlertTriangle className="w-3.5 h-3.5 text-muted-foreground shrink-0" />}
                    <span className="text-sm font-medium truncate">{item.title ?? item.url ?? item.platform}</span>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    {item.platform && <PlatformBadge platform={item.platform} />}
                    <span className={cn("text-[10px] px-2 py-0.5 rounded-full border font-semibold capitalize", RISK_COLOR[item.risk] ?? RISK_COLOR.medium)}>
                      {item.risk}
                    </span>
                  </div>
                </div>
                {item.description && (
                  <p className="text-xs text-muted-foreground/80 leading-relaxed ml-5">{item.description}</p>
                )}
                {item.evidenceSnippet && (
                  <p className="text-[11px] font-mono bg-muted/30 rounded-lg px-3 py-1.5 mt-2 text-muted-foreground/70">
                    {item.evidenceSnippet}
                  </p>
                )}
                {item.url && (
                  <div className="ml-5 mt-2">
                    <a href={item.url} target="_blank" rel="noopener noreferrer"
                      className="text-[11px] text-muted-foreground hover:text-foreground transition-colors flex items-center gap-1 w-fit">
                      <ExternalLink className="w-3 h-3" /> {item.url.slice(0, 60)}{item.url.length > 60 ? "…" : ""}
                    </a>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      ))}

      {/* Social platform monitor — always shown when no automated social results */}
      {socialResults.length === 0 && (
        <SocialPlatformMonitor scanDomain={scanDomain} />
      )}
    </div>
  );
}

const AD_RISK_META: Record<string, { label: string; color: string; bg: string; border: string }> = {
  critical: { label: "Critical", color: "text-red-400",    bg: "bg-red-500/10",    border: "border-red-500/30" },
  high:     { label: "High",     color: "text-orange-400", bg: "bg-orange-500/10", border: "border-orange-500/30" },
  medium:   { label: "Medium",   color: "text-yellow-400", bg: "bg-yellow-500/10", border: "border-yellow-500/30" },
  low:      { label: "Low",      color: "text-green-400",  bg: "bg-green-500/10",  border: "border-green-500/30" },
};

function MaliciousAdsTab({ ads, hasMetaToken }: { ads: any[]; hasMetaToken?: boolean }) {
  const highRisk = ads.filter((a: any) => a.risk === "critical" || a.risk === "high").length;
  if (ads.length === 0) {
    return (
      <div className="p-10 text-center space-y-3">
        <Megaphone className="w-8 h-8 text-muted-foreground/30 mx-auto" />
        <div>
          <p className="text-sm font-medium text-muted-foreground">No suspicious ad activity detected</p>
          <p className="text-xs text-muted-foreground/60 mt-1">
            {hasMetaToken === false ? (
              <>
                A Meta Ads access token is required to monitor the ad library.{" "}
                <a href="/settings/platform" className="text-blue-400 hover:underline">
                  Configure it in Platform Settings → Brand Intelligence.
                </a>
              </>
            ) : (
              "No brand-impersonating ads were found in the Meta Ads Library for this brand."
            )}
          </p>
        </div>
      </div>
    );
  }
  return (
    <div className="p-6 space-y-4">
      <div className="flex items-start justify-between">
        <div>
          <h3 className="text-sm font-semibold">Malicious Ad Monitoring</h3>
          <p className="text-xs text-muted-foreground mt-0.5">
            {ads.length} suspicious ad{ads.length !== 1 ? "s" : ""} detected via Meta Ads Library
            {highRisk > 0 && <span className="ml-1 text-red-400 font-medium">— {highRisk} high/critical risk</span>}
          </p>
        </div>
        <span className="text-xs px-2.5 py-1 rounded-lg bg-violet-500/10 text-violet-400 border border-violet-500/20 font-medium">
          Meta Ads Library
        </span>
      </div>
      <div className="space-y-3">
        {ads.map((ad: any, i: number) => {
          const risk = AD_RISK_META[ad.risk as string] ?? AD_RISK_META.medium;
          return (
            <div key={ad.id ?? i} className={cn("rounded-xl border p-4 space-y-3", risk.bg, risk.border)}>
              <div className="flex items-start justify-between gap-4">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap mb-1">
                    <span className={cn("text-[10px] font-bold px-2 py-0.5 rounded-full border uppercase tracking-wide", risk.color, risk.bg, risk.border)}>
                      {risk.label}
                    </span>
                    {ad.platform && (
                      <span className="text-[10px] px-2 py-0.5 rounded-full bg-muted text-muted-foreground border border-border">
                        {ad.platform}
                      </span>
                    )}
                    {ad.adType && (
                      <span className="text-[10px] px-2 py-0.5 rounded-full bg-muted/50 text-muted-foreground border border-border capitalize">
                        {ad.adType}
                      </span>
                    )}
                  </div>
                  {ad.title && (
                    <p className="text-sm font-semibold text-foreground leading-snug">{ad.title}</p>
                  )}
                  {ad.body && (
                    <p className="text-xs text-muted-foreground mt-1 leading-relaxed line-clamp-3">{ad.body}</p>
                  )}
                </div>
                {ad.snapshotUrl && (
                  <a
                    href={ad.snapshotUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center gap-1 text-[10px] text-primary hover:text-primary/80 transition-colors shrink-0"
                  >
                    <ExternalLink className="w-3 h-3" /> View Ad
                  </a>
                )}
              </div>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-[11px]">
                {ad.advertiserName && (
                  <div className="bg-background/50 rounded-lg px-2.5 py-1.5">
                    <p className="text-muted-foreground text-[10px] mb-0.5 uppercase tracking-wide">Advertiser</p>
                    <p className="font-medium truncate">{ad.advertiserName}</p>
                  </div>
                )}
                {ad.impressions && (
                  <div className="bg-background/50 rounded-lg px-2.5 py-1.5">
                    <p className="text-muted-foreground text-[10px] mb-0.5 uppercase tracking-wide">Impressions</p>
                    <p className="font-medium">{ad.impressions}</p>
                  </div>
                )}
                {ad.spend && (
                  <div className="bg-background/50 rounded-lg px-2.5 py-1.5">
                    <p className="text-muted-foreground text-[10px] mb-0.5 uppercase tracking-wide">Spend</p>
                    <p className="font-medium">{ad.spend} {ad.currency ?? ""}</p>
                  </div>
                )}
                {ad.startDate && (
                  <div className="bg-background/50 rounded-lg px-2.5 py-1.5">
                    <p className="text-muted-foreground text-[10px] mb-0.5 uppercase tracking-wide">Active From</p>
                    <p className="font-medium">{ad.startDate.slice(0, 10)}</p>
                  </div>
                )}
              </div>
              {ad.advertiserPage && (
                <a
                  href={ad.advertiserPage}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1 text-[10px] text-muted-foreground hover:text-foreground transition-colors"
                >
                  <ExternalLink className="w-3 h-3" /> Advertiser Page
                </a>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

const TAKEDOWN_STATUS_COLORS: Record<string, string> = {
  pending:     "text-yellow-400 bg-yellow-500/10 border-yellow-500/25",
  submitted:   "text-blue-400 bg-blue-500/10 border-blue-500/25",
  in_review:   "text-violet-400 bg-violet-500/10 border-violet-500/25",
  resolved:    "text-green-400 bg-green-500/10 border-green-500/25",
  rejected:    "text-red-400 bg-red-500/10 border-red-500/25",
};

function TakedownsTab({ scanDomain, results }: { scanId: number; scanDomain: string; results: any[] }) {
  const { toast } = useToast();
  const [takedowns, setTakedowns] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState({ targetDomain: "", type: "phishing", title: "", description: "" });

  const permutationSet = new Set(results.map((r: any) => r.permutation as string));

  async function fetchTakedowns() {
    setLoading(true);
    try {
      const token = getToken();
      const res = await fetch("/api/takedowns", {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (res.ok) {
        const all = await res.json() as any[];
        setTakedowns(all.filter((t: any) => t.targetDomain && permutationSet.has(t.targetDomain)));
      }
    } catch { /* ignore */ } finally {
      setLoading(false);
    }
  }

  useEffect(() => { void fetchTakedowns(); }, [scanDomain]);

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    if (!form.targetDomain.trim() || !form.title.trim()) return;
    setSubmitting(true);
    try {
      const token = getToken();
      const res = await fetch("/api/takedowns", {
        method: "POST",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify({
          type: form.type,
          targetUrl: `https://${form.targetDomain.trim()}`,
          targetDomain: form.targetDomain.trim(),
          title: form.title.trim(),
          description: form.description,
          brandAbused: scanDomain,
          priority: "high",
        }),
      });
      if (!res.ok) throw new Error("Failed");
      toast({ title: "Takedown request submitted" });
      setShowForm(false);
      setForm({ targetDomain: "", type: "phishing", title: "", description: "" });
      void fetchTakedowns();
    } catch {
      toast({ title: "Failed to submit takedown request", variant: "destructive" });
    } finally {
      setSubmitting(false);
    }
  }

  async function handleDelete(id: number) {
    if (!confirm("Delete this takedown request?")) return;
    try {
      const token = getToken();
      await fetch(`/api/takedowns/${id}`, { method: "DELETE", headers: { Authorization: `Bearer ${token}` } });
      void fetchTakedowns();
    } catch { /* ignore */ }
  }

  const liveDomains = results
    .filter((r: any) => r.hasA || r.registrationStatus === "registered" || r.registrationStatus === "active")
    .map((r: any) => r.permutation as string);

  return (
    <div className="p-6 space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-sm font-semibold">Takedown Requests</h3>
          <p className="text-xs text-muted-foreground mt-0.5">
            Submit and track DMCA/abuse takedown requests for infringing domains detected in this scan.
          </p>
        </div>
        <Button size="sm" onClick={() => setShowForm(v => !v)} className="h-8 gap-1.5">
          <Plus className="w-3.5 h-3.5" /> New Request
        </Button>
      </div>

      {showForm && (
        <form onSubmit={handleCreate} className="bg-muted/20 border border-border rounded-xl p-4 space-y-3">
          <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">New Takedown Request</p>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div>
              <label className="text-xs text-muted-foreground block mb-1">Infringing Domain *</label>
              <input
                list="td-domains-list"
                value={form.targetDomain}
                onChange={e => setForm(v => ({ ...v, targetDomain: e.target.value }))}
                placeholder="e.g. examp1e.com"
                className="w-full bg-background border border-border rounded-lg px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-primary/40"
              />
              <datalist id="td-domains-list">
                {liveDomains.map((d: string) => <option key={d} value={d} />)}
              </datalist>
            </div>
            <div>
              <label className="text-xs text-muted-foreground block mb-1">Abuse Type</label>
              <select
                value={form.type}
                onChange={e => setForm(v => ({ ...v, type: e.target.value }))}
                className="w-full bg-background border border-border rounded-lg px-3 py-1.5 text-sm focus:outline-none"
              >
                {["phishing","brand_impersonation","domain_squatting","fake_social","malware_hosting","other"].map(r => (
                  <option key={r} value={r}>{r.replace(/_/g, " ").replace(/\b\w/g, (c: string) => c.toUpperCase())}</option>
                ))}
              </select>
            </div>
          </div>
          <div>
            <label className="text-xs text-muted-foreground block mb-1">Title *</label>
            <input
              value={form.title}
              onChange={e => setForm(v => ({ ...v, title: e.target.value }))}
              placeholder={`Brand impersonation of ${scanDomain}`}
              className="w-full bg-background border border-border rounded-lg px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-primary/40"
            />
          </div>
          <div>
            <label className="text-xs text-muted-foreground block mb-1">Description</label>
            <textarea
              value={form.description}
              onChange={e => setForm(v => ({ ...v, description: e.target.value }))}
              rows={2}
              placeholder="Evidence and additional context…"
              className="w-full bg-background border border-border rounded-lg px-3 py-1.5 text-sm focus:outline-none resize-none"
            />
          </div>
          <div className="flex gap-2 justify-end">
            <Button type="button" variant="outline" size="sm" onClick={() => setShowForm(false)}>Cancel</Button>
            <Button type="submit" size="sm" disabled={submitting || !form.targetDomain.trim() || !form.title.trim()}>
              {submitting ? <Loader2 className="w-3.5 h-3.5 animate-spin mr-1" /> : null}
              Submit Request
            </Button>
          </div>
        </form>
      )}

      {loading ? (
        <div className="flex items-center justify-center h-24">
          <Loader2 className="w-5 h-5 animate-spin text-muted-foreground" />
        </div>
      ) : takedowns.length === 0 ? (
        <div className="flex flex-col items-center justify-center h-40 text-center">
          <Shield className="w-8 h-8 text-muted-foreground/20 mb-3" />
          <p className="text-sm text-muted-foreground font-medium">No takedown requests yet</p>
          <p className="text-xs text-muted-foreground/60 mt-1">
            Submit requests for domains in this scan that are infringing on <span className="font-mono">{scanDomain}</span>.
          </p>
        </div>
      ) : (
        <div className="space-y-2">
          {takedowns.map((td: any) => (
            <div key={td.id} className="flex items-start gap-3 bg-muted/10 border border-border rounded-xl px-4 py-3">
              <Shield className="w-4 h-4 text-primary mt-0.5 shrink-0" />
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-sm font-mono font-medium">{td.targetDomain ?? td.targetUrl}</span>
                  <span className={cn("text-[10px] px-2 py-0.5 rounded-full border font-semibold capitalize", TAKEDOWN_STATUS_COLORS[td.status] ?? TAKEDOWN_STATUS_COLORS.submitted)}>
                    {td.status?.replace(/_/g, " ") ?? "submitted"}
                  </span>
                  <span className="text-[10px] text-muted-foreground capitalize">{td.type?.replace(/_/g, " ")}</span>
                </div>
                <p className="text-xs font-medium mt-0.5">{td.title}</p>
                {td.description && <p className="text-xs text-muted-foreground/70 mt-0.5">{td.description}</p>}
              </div>
              <Button variant="ghost" size="sm" onClick={() => handleDelete(td.id)} className="h-7 w-7 p-0 text-muted-foreground hover:text-red-400 shrink-0">
                <Trash2 className="w-3.5 h-3.5" />
              </Button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

const WATCHLIST_TYPE_META: Record<string, { icon: React.ReactNode; label: string; color: string }> = {
  keyword:       { icon: <Tag className="w-3.5 h-3.5" />,        label: "Keyword",       color: "text-amber-400" },
  logo_url:      { icon: <Eye className="w-3.5 h-3.5" />,        label: "Logo URL",      color: "text-purple-400" },
  domain:        { icon: <Globe className="w-3.5 h-3.5" />,       label: "Domain",        color: "text-blue-400" },
  ip:            { icon: <Server className="w-3.5 h-3.5" />,      label: "IP",            color: "text-cyan-400" },
  email:         { icon: <Mail className="w-3.5 h-3.5" />,        label: "Email",         color: "text-green-400" },
  social_handle: { icon: <AtSign className="w-3.5 h-3.5" />,      label: "Social Handle", color: "text-pink-400" },
  mobile_app:    { icon: <Smartphone className="w-3.5 h-3.5" />,  label: "Mobile App",    color: "text-orange-400" },
};

const FREQ_LABEL: Record<string, string> = { daily: "Daily", weekly: "Weekly", monthly: "Monthly" };
const DAY_NAMES = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

function WatchlistDetailTab({ items, scanDomain }: { items: any[]; scanDomain: string }) {
  const [, navigate] = useLocation();
  const normalizedScanDomain = scanDomain?.toLowerCase().replace(/^www\./, "") ?? "";

  if (items.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center h-64 text-center">
        <BookmarkCheck className="w-10 h-10 text-muted-foreground/20 mb-3" />
        <p className="text-sm font-medium text-muted-foreground">No watchlist items</p>
        <p className="text-xs text-muted-foreground/60 mt-1">
          Add domains, keywords, social handles and more in the Watchlist tab on the Brand Threats page.
        </p>
        <button
          onClick={() => navigate("/brand-threats")}
          className="mt-4 inline-flex items-center gap-1.5 text-xs text-primary hover:underline"
        >
          <ArrowLeft className="w-3.5 h-3.5" /> Go to Brand Threats
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between mb-2">
        <div>
          <h2 className="text-sm font-semibold">Watchlist Items</h2>
          <p className="text-xs text-muted-foreground mt-0.5">
            All monitored brand assets — keywords, domains, social handles and more. Items marked{" "}
            <span className="text-blue-400 font-medium">This Scan</span> are matched to the current scan domain.
          </p>
        </div>
        <span className="text-xs text-muted-foreground bg-muted/40 border border-border px-2.5 py-1 rounded-full">
          {items.length} item{items.length !== 1 ? "s" : ""}
        </span>
      </div>

      {/* Items grid */}
      <div className="space-y-3">
        {items.map((item: any) => {
          const meta = WATCHLIST_TYPE_META[item.type] ?? WATCHLIST_TYPE_META["keyword"]!;
          const isThisScan = item.type === "domain" &&
            item.value.toLowerCase().replace(/^www\./, "") === normalizedScanDomain;
          const prev = item.prevScanSummary as Record<string, number> | null;

          let scheduleLabel = "—";
          if (item.frequency === "daily") {
            scheduleLabel = item.scanTime ? `Daily at ${item.scanTime}` : "Daily";
          } else if (item.frequency === "weekly") {
            const dayName = item.dayOfWeek !== null && item.dayOfWeek !== undefined ? DAY_NAMES[item.dayOfWeek] ?? "" : "";
            scheduleLabel = `Weekly${dayName ? ` · ${dayName}` : ""}${item.scanTime ? ` at ${item.scanTime}` : ""}`;
          } else if (item.frequency === "monthly") {
            scheduleLabel = `Monthly${item.dayOfMonth ? ` · day ${item.dayOfMonth}` : ""}${item.scanTime ? ` at ${item.scanTime}` : ""}`;
          }

          const hasPrevDelta = prev && Object.keys(prev).length > 0 && Object.values(prev).some(v => (v as number) !== 0);

          return (
            <div
              key={item.id}
              className={cn(
                "rounded-xl border p-4 transition-colors",
                isThisScan
                  ? "border-blue-500/25 bg-blue-500/5"
                  : "border-border bg-background/40",
              )}
            >
              <div className="flex items-start gap-3">
                {/* Type icon */}
                <div className={cn(
                  "w-8 h-8 rounded-lg border flex items-center justify-center shrink-0 mt-0.5",
                  isThisScan ? "bg-blue-500/10 border-blue-500/25" : "bg-muted/40 border-border",
                  meta.color,
                )}>
                  {meta.icon}
                </div>

                {/* Main content */}
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
                      {meta.label}
                    </span>
                    {isThisScan && (
                      <span className="inline-flex items-center gap-1 text-[10px] font-semibold px-1.5 py-0.5 rounded-full bg-blue-500/10 border border-blue-500/20 text-blue-400">
                        <Shield className="w-2.5 h-2.5" /> This Scan
                      </span>
                    )}
                    {item.lastScanId && (
                      <a
                        href={`/brand-threats/${item.lastScanId}`}
                        className="inline-flex items-center gap-1 text-[10px] text-primary/70 hover:text-primary transition-colors"
                      >
                        <ExternalLink className="w-2.5 h-2.5" /> Last scan
                      </a>
                    )}
                  </div>

                  <p className="text-sm font-mono font-semibold mt-0.5 truncate">{item.value}</p>

                  {item.notes && (
                    <p className="text-xs text-muted-foreground mt-1 leading-relaxed">{item.notes}</p>
                  )}

                  {/* Schedule + timing row */}
                  <div className="flex items-center gap-4 mt-2 flex-wrap">
                    {item.frequency && (
                      <span className="flex items-center gap-1 text-[11px] text-muted-foreground">
                        <Clock className="w-3 h-3" />
                        {FREQ_LABEL[item.frequency] ?? item.frequency}
                        {scheduleLabel !== FREQ_LABEL[item.frequency] && (
                          <span className="text-muted-foreground/60 ml-0.5">· {item.scanTime}{item.dayOfWeek !== null && item.dayOfWeek !== undefined ? ` ${DAY_NAMES[item.dayOfWeek] ?? ""}` : ""}{item.dayOfMonth ? ` day ${item.dayOfMonth}` : ""}</span>
                        )}
                      </span>
                    )}
                    {item.lastScanAt && (
                      <span className="flex items-center gap-1 text-[11px] text-muted-foreground">
                        <RotateCw className="w-3 h-3" />
                        Last: {formatDate(item.lastScanAt)}
                      </span>
                    )}
                    {item.nextScanAt && (
                      <span className="flex items-center gap-1 text-[11px] text-muted-foreground">
                        <Calendar className="w-3 h-3" />
                        Next: {formatDate(item.nextScanAt)}
                      </span>
                    )}
                    {!item.frequency && !item.lastScanAt && (
                      <span className="text-[11px] text-muted-foreground/50">No schedule · manual scan only</span>
                    )}
                  </div>

                  {/* Previous scan delta */}
                  {hasPrevDelta && (
                    <div className="mt-2 flex items-center gap-3 flex-wrap">
                      <span className="text-[10px] text-muted-foreground font-medium">Changes vs. prev scan:</span>
                      {Object.entries(prev!).map(([k, v]) => {
                        if (v === 0) return null;
                        const isPos = (v as number) > 0;
                        return (
                          <span
                            key={k}
                            className={cn(
                              "inline-flex items-center gap-1 text-[10px] font-semibold px-1.5 py-0.5 rounded-full border",
                              isPos
                                ? "bg-red-500/10 border-red-500/20 text-red-400"
                                : "bg-green-500/10 border-green-500/20 text-green-400",
                            )}
                          >
                            {isPos ? "+" : ""}{v as number} {k.replace(/_/g, " ")}
                          </span>
                        );
                      })}
                    </div>
                  )}
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {/* Footer note */}
      <div className="mt-4 rounded-xl border border-border bg-muted/20 px-4 py-3 flex items-start gap-2">
        <Info className="w-3.5 h-3.5 text-muted-foreground shrink-0 mt-0.5" />
        <p className="text-xs text-muted-foreground leading-relaxed">
          Watchlist items are scanned on their configured schedule. Each completed scan updates the{" "}
          <strong>Last Scan</strong> timestamp and computes a delta against the previous scan result, shown as change badges above.
          Manage items and schedules from the{" "}
          <button onClick={() => navigate("/brand-threats")} className="text-primary hover:underline">Brand Threats</button>{" "}
          Watchlist tab.
        </p>
      </div>
    </div>
  );
}

export default function BrandThreatDetailPage() {
  const params = useParams<{ id: string }>();
  const [, navigate] = useLocation();
  const id = parseInt(params.id ?? "0", 10);
  const [filter, setFilter] = useState<FilterMode>("all");
  const [fuzzerFilter, setFuzzerFilter] = useState<string>("all");
  const [expandedId, setExpandedId] = useState<number | null>(null);
  const [page, setPage] = useState(0);
  const [search, setSearch] = useState("");
  const [downloading, setDownloading] = useState(false);
  const [downloadingCsv, setDownloadingCsv] = useState(false);
  const [activeTab, setActiveTab] = useState<TabMode>("typosquatting");
  const [watchlistItem, setWatchlistItem] = useState<any | null>(null);
  const [allWatchlistItems, setAllWatchlistItems] = useState<any[]>([]);
  const [confirmDeleteScan, setConfirmDeleteScan] = useState(false);
  const deleteScan = useDeleteBrandThreatScan();
  const qc = useQueryClient();
  const { toast } = useToast();
  const PAGE_SIZE = 50;

  const { data: scan, isLoading, refetch } = useGetBrandThreatScan(id, {
    query: {
      enabled: !!id,
      queryKey: getGetBrandThreatScanQueryKey(id),
      staleTime: 0,
      refetchInterval: (query: any) => {
        const d = query?.state?.data as any;
        if (!d || d?.status === "running" || d?.status === "pending") return 3000;
        if (d?.favihunterStatus === "running" || d?.favihunterStatus === "pending") return 4000;
        return false;
      },
    },
  });

  const s = scan as any;

  const { data: allScans = [] } = useListBrandThreats({});

  const domainScans = useMemo(() => {
    if (!s?.domain) return [];
    const domain = s.domain.toLowerCase().replace(/^www\./, "");
    return ((allScans as any[]) ?? [])
      .filter((sc: any) => (sc.domain ?? "").toLowerCase().replace(/^www\./, "") === domain)
      .sort((a: any, b: any) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
  }, [allScans, s?.domain]);

  useEffect(() => {
    void fetch("/api/brand-watchlist", {
      headers: { Authorization: `Bearer ${getToken() ?? ""}` },
    })
      .then(r => r.ok ? r.json() : [])
      .then((items: any[]) => {
        setAllWatchlistItems(items);
        if (s?.domain) {
          const domain = s.domain.toLowerCase().replace(/^www\./, "");
          const match = items.find((i: any) =>
            i.type === "domain" &&
            i.value.toLowerCase().replace(/^www\./, "") === domain,
          );
          setWatchlistItem(match ?? null);
        }
      })
      .catch(() => {});
  }, [s?.domain]);
  const results: any[] = s?.results ?? [];
  const phishingDetections: any[] = s?.phishingDetections ?? [];
  const dataLeaks: any[] = s?.dataLeaks ?? [];
  const brandAbuse: any[] = s?.brandAbuse ?? [];
  const adMonitoringResults: any[] = s?.adMonitoringResults ?? [];

  const filtered = results.filter((r: any) => {
    if (filter === "live"       && !(r.dnsA?.length > 0)) return false;
    if (filter === "mx"         && !(r.dnsMx?.length > 0)) return false;
    if (filter === "suspicious" && !r.isSuspicious) return false;
    if (filter === "phishing"   && !r.isPhishing) return false;
    if (fuzzerFilter !== "all"  && r.fuzzer !== fuzzerFilter) return false;
    if (search && !r.permutation.includes(search.toLowerCase())) return false;
    return true;
  });

  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const paged = filtered.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);

  if (isLoading) {
    return <div className="flex items-center justify-center h-64"><Loader2 className="w-5 h-5 animate-spin text-muted-foreground" /></div>;
  }

  if (!s) {
    return (
      <div className="p-6 flex flex-col gap-3">
        <Button variant="ghost" size="sm" onClick={() => navigate("/brand-threats")} className="w-fit">
          <ArrowLeft className="w-3.5 h-3.5 mr-1.5" /> Back
        </Button>
        <p className="text-muted-foreground text-sm">Scan not found.</p>
      </div>
    );
  }

  const fuzzerBreakdown: Record<string, number> = s.fuzzerBreakdown ?? {};
  const liveResults = results.filter((r: any) => r.dnsA?.length > 0);
  const mxResults   = results.filter((r: any) => r.dnsMx?.length > 0);
  const suspResults = results.filter((r: any) => r.isSuspicious);
  const phishResults = results.filter((r: any) => r.isPhishing);
  const risk        = RISK_META[s.phishingRisk] ?? RISK_META.low;

  const chartData = Object.entries(fuzzerBreakdown)
    .sort(([, a], [, b]) => (b as number) - (a as number))
    .map(([fuzzer, count]) => ({
      fuzzer,
      label: FUZZER_META[fuzzer]?.label ?? fuzzer,
      count: count as number,
      color: FUZZER_META[fuzzer]?.chartColor ?? "#94a3b8",
    }));

  const shodanCloneCount = (s?.faviconShodanMatches as any[] | null)?.length ?? 0;
  const faviconPivotCount = s?.faviconSearchUrls ? Object.keys(s.faviconSearchUrls as object).filter(k => k !== "_error").length : 0;
  const hasFaviconData = !!(s?.faviconMd5 || s?.favihunterStatus === "done");

  const pipelineSubdomains: string[] = Array.isArray(s?.pipelineSubdomains) ? (s.pipelineSubdomains as string[]) : [];

  const TABS: { id: TabMode; label: string; icon: React.ReactNode; count?: number; color?: string }[] = [
    { id: "typosquatting", label: "Typosquatting", icon: <Globe className="w-3.5 h-3.5" />, count: results.length },
    { id: "phishing",      label: "Phishing",      icon: <Fish className="w-3.5 h-3.5" />,  count: phishingDetections.length, color: phishingDetections.length > 0 ? "text-red-400" : undefined },
    { id: "data_leaks",    label: "Data Leaks",    icon: <Database className="w-3.5 h-3.5" />, count: dataLeaks.length, color: dataLeaks.length > 0 ? "text-orange-400" : undefined },
    { id: "brand_abuse",   label: "Brand Abuse",   icon: <Target className="w-3.5 h-3.5" />,   count: brandAbuse.length, color: brandAbuse.length > 0 ? "text-yellow-400" : undefined },
    { id: "malicious_ads", label: "Malicious Ads", icon: <Megaphone className="w-3.5 h-3.5" />, count: adMonitoringResults.length, color: adMonitoringResults.length > 0 ? "text-violet-400" : undefined },
    ...(hasFaviconData ? [{ id: "favicon_clones" as TabMode, label: "Favicon Clones", icon: <Fingerprint className="w-3.5 h-3.5" />, count: shodanCloneCount, color: shodanCloneCount > 0 ? "text-violet-400" : undefined }] : []),
    ...(pipelineSubdomains.length > 0 ? [{ id: "subdomains" as TabMode, label: "Subdomains", icon: <Server className="w-3.5 h-3.5" />, count: pipelineSubdomains.length, color: "text-blue-400" }] : []),
    { id: "watchlist",     label: "Watchlist",     icon: <BookmarkCheck className="w-3.5 h-3.5" />, count: allWatchlistItems.length, color: allWatchlistItems.length > 0 ? "text-blue-400" : undefined },
    { id: "takedowns",     label: "Takedowns",     icon: <Shield className="w-3.5 h-3.5" /> },
  ];

  return (
    <div className="flex flex-col h-full min-h-0">
      {/* ── Hero header ────────────────────────────────────────────────────── */}
      <div className="bg-gradient-to-r from-card via-card to-background border-b border-border px-6 py-5 shrink-0">
        <div className="flex items-center gap-3 mb-1">
          <Button variant="ghost" size="sm" onClick={() => navigate("/brand-threats")} className="h-8 shrink-0">
            <ArrowLeft className="w-3.5 h-3.5 mr-1" /> Back
          </Button>
          <div className="w-px h-4 bg-border" />
          <ShieldAlert className="w-4 h-4 text-primary shrink-0" />
          <h1 className="text-lg font-bold font-mono truncate">{s.domain}</h1>
          {s.status === "running" && (
            <span className="flex items-center gap-1.5 text-xs text-blue-400 bg-blue-500/10 border border-blue-500/20 px-2 py-0.5 rounded-full shrink-0">
              <Loader2 className="w-3 h-3 animate-spin" /> Scanning…
            </span>
          )}
          {s.status === "done" && s.phishingRisk && (
            <span className={cn("text-xs px-2.5 py-0.5 rounded-full border font-semibold capitalize shrink-0", risk.color, risk.bg, risk.border)}>
              {risk.label} Risk
            </span>
          )}
          {s.status === "error" && (
            <span className="flex items-center gap-1 text-xs text-red-400 bg-red-500/10 border border-red-500/20 px-2 py-0.5 rounded-full shrink-0">
              <XCircle className="w-3 h-3" /> Error
            </span>
          )}
          {watchlistItem && (
            <span className="flex items-center gap-1 text-xs text-blue-400 bg-blue-500/10 border border-blue-500/20 px-2 py-0.5 rounded-full shrink-0">
              <Shield className="w-3 h-3" /> Watchlist
            </span>
          )}
          <div className="flex-1" />
          <Button
            variant="outline" size="sm" className="h-8 shrink-0 gap-1.5"
            disabled={downloadingCsv || s.status !== "done"}
            onClick={async () => {
              setDownloadingCsv(true);
              try { await downloadBrandThreatCsv(id, getToken()); }
              catch { /* ignore */ }
              finally { setDownloadingCsv(false); }
            }}
          >
            {downloadingCsv ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Download className="w-3.5 h-3.5" />}
            {downloadingCsv ? "Exporting…" : "CSV"}
          </Button>
          <Button
            variant="outline" size="sm" className="h-8 shrink-0 gap-1.5"
            disabled={downloading || s.status !== "done"}
            onClick={async () => {
              setDownloading(true);
              try { await downloadBrandThreatPdf(id, getToken()); }
              catch { /* ignore */ }
              finally { setDownloading(false); }
            }}
          >
            {downloading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Download className="w-3.5 h-3.5" />}
            {downloading ? "Generating…" : "PDF"}
          </Button>
          <Button variant="outline" size="sm" onClick={() => refetch()} className="h-8 shrink-0">
            <RefreshCw className="w-3.5 h-3.5 mr-1.5" /> Refresh
          </Button>
          <Button
            variant="outline" size="sm"
            className="h-8 shrink-0 gap-1.5"
            disabled={s.status === "running" || s.status === "pending"}
            onClick={async () => {
              try {
                await fetch(`/api/brand-threats/${id}/rescan`, {
                  method: "POST",
                  headers: { Authorization: `Bearer ${getToken() ?? ""}` },
                });
                void refetch();
              } catch { /* ignore */ }
            }}
          >
            <RefreshCw className="w-3.5 h-3.5" />
            Re-scan
          </Button>
          <Button
            variant="outline" size="sm"
            className="h-8 shrink-0 gap-1.5 text-destructive hover:text-destructive border-destructive/30 hover:bg-destructive/10"
            onClick={() => setConfirmDeleteScan(true)}
          >
            <Trash2 className="w-3.5 h-3.5" /> Delete
          </Button>
          <Dialog open={confirmDeleteScan} onOpenChange={setConfirmDeleteScan}>
            <DialogContent>
              <DialogHeader>
                <DialogTitle className="flex items-center gap-2">
                  <AlertTriangle className="w-5 h-5 text-destructive" /> Delete Scan?
                </DialogTitle>
              </DialogHeader>
              <p className="text-sm text-muted-foreground">
                Permanently delete this brand threat scan and all associated results? This cannot be undone.
              </p>
              <DialogFooter className="mt-2">
                <Button variant="outline" onClick={() => setConfirmDeleteScan(false)} disabled={deleteScan.isPending}>Cancel</Button>
                <Button
                  variant="destructive"
                  onClick={async () => {
                    try {
                      await deleteScan.mutateAsync({ id });
                      qc.invalidateQueries({ queryKey: getListBrandThreatsQueryKey() });
                      navigate("/brand-threats");
                    } finally {
                      setConfirmDeleteScan(false);
                    }
                  }}
                  disabled={deleteScan.isPending}
                >
                  {deleteScan.isPending ? "Deleting…" : "Delete"}
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>
        </div>

        <p className="text-xs text-muted-foreground mt-2 ml-[72px]">
          Started {formatDate(s.createdAt)}
          {s.completedAt && ` · Completed ${formatDate(s.completedAt)}`}
          {s.pipelineScanId && (
            <span className="ml-2 inline-flex items-center gap-0.5 text-violet-400">
              <Zap className="w-2.5 h-2.5" /> Auto-triggered from pipeline scan #{s.pipelineScanId}
            </span>
          )}
          {watchlistItem?.lastScanAt && (
            <span className="ml-2 inline-flex items-center gap-0.5 text-blue-400/70">
              <Shield className="w-2.5 h-2.5" />
              Last auto-scan: {formatDate(watchlistItem.lastScanAt)}
              {watchlistItem.nextScanAt && ` · Next: ${formatDate(watchlistItem.nextScanAt)}`}
            </span>
          )}
        </p>

        {/* ── Scan History Picker ──────────────────────────────────────────────── */}
        {domainScans.length > 1 && (
          <div className="flex items-center gap-2 mt-2 ml-[72px] flex-wrap">
            <History className="w-3.5 h-3.5 text-muted-foreground/60 shrink-0" />
            <span className="text-xs text-muted-foreground shrink-0">Scan history:</span>
            <select
              value={id}
              onChange={e => navigate(`/brand-threats/${e.target.value}`)}
              className="text-xs bg-card border border-border rounded px-2 py-0.5 text-foreground cursor-pointer max-w-[300px]"
            >
              {domainScans.map((sc: any, i: number) => (
                <option key={sc.id} value={sc.id}>
                  {i === 0 ? "▲ Latest — " : `#${domainScans.length - i} — `}{formatDate(sc.createdAt)} · {sc.status === "done" ? `${sc.totalPermutations ?? 0} permutations` : sc.status}
                </option>
              ))}
            </select>
            <span className="text-xs text-muted-foreground/50 shrink-0">
              {domainScans.length} total scan{domainScans.length !== 1 ? "s" : ""}
            </span>
            {/* Jump to latest button when viewing an older scan */}
            {domainScans.length > 0 && String(domainScans[0].id) !== String(id) && (
              <button
                onClick={() => navigate(`/brand-threats/${domainScans[0].id}`)}
                className="inline-flex items-center gap-1 text-[10px] font-medium px-2 py-0.5 rounded-full bg-primary/10 border border-primary/25 text-primary hover:bg-primary/20 transition-colors"
              >
                Jump to latest ↑
              </button>
            )}
          </div>
        )}

        {/* ── "Viewing older scan" comparison banner ───────────────────────────── */}
        {domainScans.length > 1 && String(domainScans[0]?.id) !== String(id) && s.status === "done" && (() => {
          const latest = domainScans[0] as any;
          if (!latest || latest.status !== "done") return null;
          const deltaPerms  = (latest.totalPermutations ?? 0) - (s.totalPermutations ?? 0);
          const deltaLive   = (latest.liveCount ?? 0)         - (s.liveCount ?? 0);
          const deltaPhish  = (latest.phishingCount ?? 0)     - (s.phishingCount ?? 0);
          const deltaLeaks  = (latest.dataLeakCount ?? 0)     - (s.dataLeakCount ?? 0);
          const deltaAbuse  = (latest.brandAbuseCount ?? 0)   - (s.brandAbuseCount ?? 0);
          const hasChanges  = deltaPerms !== 0 || deltaLive !== 0 || deltaPhish !== 0 || deltaLeaks !== 0 || deltaAbuse !== 0;
          const totalNew    = Math.max(0, deltaLive) + Math.max(0, deltaPhish) + Math.max(0, deltaLeaks) + Math.max(0, deltaAbuse);
          return (
            <div className={cn(
              "mx-6 mt-3 border rounded-xl p-3.5 shrink-0",
              totalNew > 0
                ? "bg-orange-500/5 border-orange-500/20"
                : "bg-blue-500/5 border-blue-500/20",
            )}>
              <div className="flex items-center justify-between gap-3 flex-wrap">
                <div className="flex items-center gap-2">
                  <TrendingUp className={cn("w-3.5 h-3.5 shrink-0", totalNew > 0 ? "text-orange-400" : "text-blue-400")} />
                  <p className={cn("text-xs font-semibold", totalNew > 0 ? "text-orange-300" : "text-blue-300")}>
                    Viewing scan from {formatDate(s.createdAt)} — comparing with latest scan ({formatDate(latest.createdAt)})
                  </p>
                </div>
                <button
                  onClick={() => navigate(`/brand-threats/${latest.id}`)}
                  className="text-[10px] font-medium text-primary hover:text-primary/80 underline shrink-0"
                >
                  View latest →
                </button>
              </div>
              {hasChanges && (
                <div className="flex flex-wrap gap-3 mt-2 ml-5.5">
                  {[
                    { label: "Permutations", delta: deltaPerms, warn: false },
                    { label: "Live Domains",  delta: deltaLive,  warn: true },
                    { label: "Phishing",      delta: deltaPhish, warn: true },
                    { label: "Data Leaks",    delta: deltaLeaks, warn: true },
                    { label: "Brand Abuse",   delta: deltaAbuse, warn: true },
                  ].filter(m => m.delta !== 0).map(m => (
                    <div key={m.label} className="flex items-center gap-1">
                      <span className="text-[10px] text-muted-foreground">{m.label}:</span>
                      <span className={cn(
                        "text-[10px] font-bold",
                        m.delta > 0 && m.warn ? "text-orange-400" : m.delta > 0 ? "text-blue-400" : "text-green-400",
                      )}>
                        {m.delta > 0 ? "+" : ""}{m.delta} in latest
                      </span>
                    </div>
                  ))}
                  {!hasChanges && (
                    <span className="text-[10px] text-muted-foreground">No changes between scans</span>
                  )}
                </div>
              )}
              {!hasChanges && (
                <p className="text-[11px] text-muted-foreground mt-1 ml-5.5">No changes detected between this scan and the latest.</p>
              )}
            </div>
          );
        })()}

        {s.status === "done" && (
          <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 mt-5">
            {[
              { label: "Permutations", value: (s.totalPermutations ?? 0).toLocaleString(), color: "", sub: "total" },
              { label: "Live Domains", value: liveResults.length, color: liveResults.length > 0 ? "text-red-400" : "text-green-400", sub: "DNS A resolves" },
              { label: "Phishing Ready", value: mxResults.length, color: mxResults.length > 0 ? "text-orange-400" : "text-green-400", sub: "Has MX records" },
              { label: "Confirmed Phishing", value: phishingDetections.length, color: phishingDetections.length > 0 ? "text-red-400" : "text-green-400", sub: "feed verified" },
              { label: "Data Breaches", value: dataLeaks.length, color: dataLeaks.length > 0 ? "text-yellow-400" : "text-green-400", sub: "HIBP matches" },
            ].map(stat => (
              <div key={stat.label} className="bg-background/60 border border-border rounded-xl px-4 py-3">
                <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-0.5">{stat.label}</p>
                <p className={cn("text-2xl font-bold tabular-nums", stat.color)}>{stat.value}</p>
                <p className="text-[10px] text-muted-foreground">{stat.sub}</p>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* ── Watchlist delta banner — shown after a scheduled re-scan ─────────── */}
      {watchlistItem?.prevScanSummary && s.status === "done" && (() => {
        const prev = watchlistItem.prevScanSummary as Record<string, number>;
        const deltaLive    = (s.liveCount ?? 0)         - (prev.liveCount ?? 0);
        const deltaPhish   = (s.phishingCount ?? 0)     - (prev.phishingCount ?? 0);
        const deltaLeaks   = (s.dataLeakCount ?? 0)     - (prev.dataLeakCount ?? 0);
        const deltaAbuse   = (s.brandAbuseCount ?? 0)   - (prev.brandAbuseCount ?? 0);
        const totalNew     = Math.max(0, deltaLive) + Math.max(0, deltaPhish) + Math.max(0, deltaLeaks) + Math.max(0, deltaAbuse);
        const hasChanges   = deltaLive !== 0 || deltaPhish !== 0 || deltaLeaks !== 0 || deltaAbuse !== 0;
        if (!hasChanges) return null;
        return (
          <div className={cn(
            "mx-6 mt-4 border rounded-xl p-4 shrink-0",
            totalNew > 0
              ? "bg-orange-500/5 border-orange-500/20"
              : "bg-green-500/5 border-green-500/20",
          )}>
            <div className="flex items-center gap-2 mb-2">
              <TrendingUp className={cn("w-4 h-4 shrink-0", totalNew > 0 ? "text-orange-400" : "text-green-400")} />
              <p className={cn("text-sm font-semibold", totalNew > 0 ? "text-orange-400" : "text-green-400")}>
                {totalNew > 0
                  ? `${totalNew} new threat${totalNew !== 1 ? "s" : ""} found since last scheduled scan`
                  : "No new threats found since last scheduled scan"}
              </p>
            </div>
            <div className="flex flex-wrap gap-3 ml-6">
              {[
                { label: "Live domains",  delta: deltaLive,  warn: deltaLive > 0 },
                { label: "Phishing",      delta: deltaPhish, warn: deltaPhish > 0 },
                { label: "Data leaks",    delta: deltaLeaks, warn: deltaLeaks > 0 },
                { label: "Brand abuse",   delta: deltaAbuse, warn: deltaAbuse > 0 },
              ].filter(d => d.delta !== 0).map(d => (
                <span key={d.label} className={cn(
                  "text-[11px] font-semibold px-2 py-1 rounded-lg border",
                  d.warn
                    ? "text-orange-400 bg-orange-500/10 border-orange-500/20"
                    : "text-green-400 bg-green-500/10 border-green-500/20",
                )}>
                  {d.delta > 0 ? `+${d.delta}` : d.delta} {d.label}
                </span>
              ))}
            </div>
          </div>
        );
      })()}

      {/* ── Status banners ──────────────────────────────────────────────────── */}
      {(s.status === "running" || s.status === "pending") && (
        <div className="mx-6 mt-4 bg-blue-500/5 border border-blue-500/20 rounded-xl p-4 flex items-center gap-4 shrink-0">
          <Loader2 className="w-5 h-5 animate-spin text-blue-400 shrink-0" />
          <div>
            <p className="text-sm font-medium text-blue-400">Full intelligence scan in progress</p>
            <p className="text-xs text-muted-foreground">
              {s.totalPermutations > 0
                ? `Resolving DNS for ${s.totalPermutations} domain permutations + running RDAP, GeoIP, VT, phishing feeds, HIBP, brand abuse checks…`
                : "Generating permutations via dnstwist + running favihunter favicon analysis…"}
            </p>
          </div>
        </div>
      )}
      {s.status === "error" && (() => {
        const isTimeout = s.error?.toLowerCase().includes("timed out");
        return (
          <div className="mx-6 mt-4 bg-red-500/5 border border-red-500/20 rounded-xl p-4 shrink-0">
            <div className="flex items-start gap-3">
              <AlertTriangle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
              <div className="flex-1 min-w-0">
                <p className="text-sm font-semibold text-red-400">
                  {isTimeout ? "Scan timed out" : "Scan failed"}
                </p>
                <p className="text-xs text-muted-foreground mt-1 font-mono">
                  {s.error ?? "An unexpected error occurred during the scan."}
                </p>
                {isTimeout && (
                  <p className="text-xs text-muted-foreground/70 mt-1">
                    This scan was automatically stopped after exceeding the 30-minute limit. Click Retry Scan to start a fresh scan and get up-to-date results.
                  </p>
                )}
              </div>
              <Button
                size="sm"
                variant="outline"
                className="shrink-0 h-8 gap-1.5 border-red-500/30 text-red-400 hover:bg-red-500/10 hover:text-red-300"
                onClick={async () => {
                  try {
                    const res = await fetch(`/api/brand-threats/${id}/rescan`, {
                      method: "POST",
                      headers: { Authorization: `Bearer ${getToken() ?? ""}` },
                    });
                    if (!res.ok) {
                      const body = await res.json().catch(() => ({}));
                      toast({ title: body?.error ?? "Failed to start retry", variant: "destructive" });
                      return;
                    }
                    const newScan = await res.json();
                    toast({ title: "Scan restarted", description: `A fresh scan has been queued for ${newScan.domain ?? s.domain}.` });
                    if (newScan.id && newScan.id !== id) {
                      navigate(`/brand-threats/${newScan.id}`);
                    } else {
                      void refetch();
                    }
                  } catch {
                    toast({ title: "Failed to retry scan", variant: "destructive" });
                  }
                }}
              >
                <RefreshCw className="w-3.5 h-3.5" />
                Retry Scan
              </Button>
            </div>
          </div>
        );
      })()}

      {/* ── Scan History ─────────────────────────────────────────────────────── */}
      {(() => {
        const history: any[] = s?.scanHistory ?? [];
        if (history.length === 0) return null;
        return (
          <div className="mx-6 mt-4 shrink-0">
            <details className="group bg-muted/20 border border-border rounded-xl overflow-hidden">
              <summary className="flex items-center gap-2 px-4 py-2.5 cursor-pointer select-none text-xs font-semibold text-muted-foreground hover:text-foreground transition-colors list-none">
                <History className="w-3.5 h-3.5" />
                Previous Scan Rounds
                <span className="ml-1 bg-muted text-muted-foreground px-1.5 py-0.5 rounded-full text-[10px] font-bold">{history.length}</span>
                <span className="ml-auto text-muted-foreground/50 text-[10px] group-open:hidden">▶ expand</span>
                <span className="ml-auto text-muted-foreground/50 text-[10px] hidden group-open:inline">▼ collapse</span>
              </summary>
              <div className="border-t border-border">
                <div className="overflow-x-auto">
                  <table className="w-full text-xs">
                    <thead>
                      <tr className="bg-muted/30">
                        <th className="text-left px-4 py-2 text-muted-foreground font-medium">Scan Date</th>
                        <th className="text-right px-4 py-2 text-muted-foreground font-medium">Total</th>
                        <th className="text-right px-4 py-2 text-muted-foreground font-medium">Registered</th>
                        <th className="text-right px-4 py-2 text-muted-foreground font-medium">High Risk</th>
                        <th className="text-right px-4 py-2 text-muted-foreground font-medium">Phishing</th>
                      </tr>
                    </thead>
                    <tbody>
                      {history.map((h: any, i: number) => (
                        <tr key={i} className="border-t border-border/50 hover:bg-muted/20 transition-colors">
                          <td className="px-4 py-2 text-foreground/80">{formatDate(h.archivedAt)}</td>
                          <td className="px-4 py-2 text-right text-foreground/70">{h.total.toLocaleString()}</td>
                          <td className="px-4 py-2 text-right">
                            <span className={h.registered > 0 ? "text-orange-400 font-medium" : "text-muted-foreground"}>{h.registered}</span>
                          </td>
                          <td className="px-4 py-2 text-right">
                            <span className={h.highRisk > 0 ? "text-red-400 font-medium" : "text-muted-foreground"}>{h.highRisk}</span>
                          </td>
                          <td className="px-4 py-2 text-right">
                            <span className={h.phishing > 0 ? "text-red-500 font-bold" : "text-muted-foreground"}>{h.phishing}</span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </details>
          </div>
        );
      })()}


      {/* ── Tab navigation ──────────────────────────────────────────────────── */}
      {s.status === "done" && (
        <div className="px-6 pt-4 shrink-0">
          <div className="flex items-center gap-1 bg-muted/30 rounded-xl p-1 w-fit">
            {TABS.map(tab => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={cn(
                  "flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-medium transition-all",
                  activeTab === tab.id
                    ? "bg-card shadow-sm text-foreground border border-border"
                    : "text-muted-foreground hover:text-foreground hover:bg-muted/50",
                )}
              >
                <span className={cn(activeTab === tab.id ? "text-primary" : "text-muted-foreground", tab.color && activeTab !== tab.id ? tab.color : "")}>
                  {tab.icon}
                </span>
                {tab.label}
                {tab.count !== undefined && (
                  <span className={cn(
                    "text-[10px] font-bold px-1.5 py-0.5 rounded-full min-w-[18px] text-center",
                    activeTab === tab.id ? "bg-primary/10 text-primary" : "bg-muted text-muted-foreground",
                    tab.color && tab.count > 0 ? "bg-current/10" : "",
                  )}>
                    {tab.count}
                  </span>
                )}
              </button>
            ))}
          </div>
        </div>
      )}

      {/* ── Tab content ─────────────────────────────────────────────────────── */}
      <div className="flex-1 min-h-0 overflow-hidden">

        {/* ── PHISHING tab ── */}
        {activeTab === "phishing" && s.status === "done" && (
          <div className="h-full overflow-y-auto">
            <PhishingTab phishing={phishingDetections} />
          </div>
        )}

        {/* ── DATA LEAKS tab ── */}
        {activeTab === "data_leaks" && s.status === "done" && (
          <div className="h-full overflow-y-auto">
            <DataLeaksTab leaks={dataLeaks} />
          </div>
        )}

        {/* ── BRAND ABUSE tab ── */}
        {activeTab === "brand_abuse" && s.status === "done" && (
          <div className="h-full overflow-y-auto">
            <BrandAbuseTab abuse={brandAbuse} warnings={Array.isArray(s.scanWarnings) ? (s.scanWarnings as ScanWarning[]) : undefined} scanDomain={s.domain} />
          </div>
        )}

        {/* ── MALICIOUS ADS tab ── */}
        {activeTab === "malicious_ads" && s.status === "done" && (
          <div className="h-full overflow-y-auto">
            <MaliciousAdsTab ads={adMonitoringResults} hasMetaToken={s.metaAdsChecked ?? undefined} />
          </div>
        )}

        {/* ── WATCHLIST tab ── */}
        {activeTab === "watchlist" && (
          <div className="h-full overflow-y-auto p-6">
            <WatchlistDetailTab items={allWatchlistItems} scanDomain={s.domain} />
          </div>
        )}

        {/* ── TAKEDOWNS tab ── */}
        {activeTab === "takedowns" && s.status === "done" && (
          <div className="h-full overflow-y-auto">
            <TakedownsTab scanId={Number(id)} scanDomain={s.domain} results={results} />
          </div>
        )}

        {/* ── FAVICON CLONES tab ── */}
        {activeTab === "favicon_clones" && (
          <div className="h-full overflow-y-auto p-6 space-y-6">
            {/* Favicon identity card */}
            {s.faviconMd5 ? (
              <>
                <div className="flex items-start gap-6 p-5 bg-violet-500/5 border border-violet-500/20 rounded-xl">
                  <div className="shrink-0 flex flex-col items-center gap-2">
                    <div className="w-16 h-16 rounded-xl border border-border bg-background flex items-center justify-center overflow-hidden">
                      {s.faviconUrl
                        ? <img src={s.faviconUrl} alt="favicon" className="w-14 h-14 object-contain" onError={e => { (e.target as HTMLImageElement).style.display = "none"; }} />
                        : <Fingerprint className="w-8 h-8 text-violet-400/40" />
                      }
                    </div>
                    <span className="text-[9px] text-muted-foreground font-mono">favicon.ico</span>
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-3">
                      <Fingerprint className="w-4 h-4 text-violet-400 shrink-0" />
                      <span className="text-sm font-semibold text-violet-300">Favicon Fingerprint</span>
                      <span className="text-[10px] text-violet-400/60 bg-violet-500/10 border border-violet-500/20 px-1.5 py-0.5 rounded-full font-mono">powered by favihunter</span>
                    </div>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-1.5">
                      {s.faviconMmh3 && <HashChip label="MMH3 (Shodan / FOFA)" value={String(s.faviconMmh3)} />}
                      {s.faviconMmh3Hex && <HashChip label="MMH3-HEX (Criminal IP)" value={s.faviconMmh3Hex} />}
                      {s.faviconMd5 && <HashChip label="MD5 (Censys / Hunter-How / ODIN)" value={s.faviconMd5} />}
                      {s.faviconSha256 && <HashChip label="SHA256 (Netlas)" value={s.faviconSha256} />}
                    </div>
                  </div>
                </div>

                {/* Search engine pivot links */}
                {s.faviconSearchUrls && Object.keys(s.faviconSearchUrls as object).filter(k => k !== "_error").length > 0 && (
                  <div className="border border-border rounded-xl p-5">
                    <div className="flex items-center gap-2 mb-3">
                      <Search className="w-4 h-4 text-muted-foreground" />
                      <span className="text-sm font-semibold">Search Engine Pivots</span>
                      <span className="text-xs text-muted-foreground ml-1">— find hosts using the same favicon fingerprint</span>
                    </div>
                    <div className="flex flex-wrap gap-2">
                      {Object.entries(s.faviconSearchUrls as Record<string, { url: string; hash_type: string }>)
                        .filter(([k]) => k !== "_error")
                        .map(([name, { url, hash_type }]) => {
                          const meta = ENGINE_META[name] ?? { color: "text-muted-foreground", bg: "bg-muted/50", border: "border-border" };
                          return (
                            <a key={name} href={url} target="_blank" rel="noopener noreferrer"
                              className={cn("flex items-center gap-1.5 px-3 py-2 rounded-lg border text-sm font-medium transition-all hover:scale-105 hover:shadow-sm", meta.color, meta.bg, meta.border)}
                              title={`Search ${name} using ${hash_type} hash`}
                            >
                              {name} <ExternalLink className="w-3.5 h-3.5 opacity-60" />
                            </a>
                          );
                        })}
                    </div>
                    <p className="text-[10px] text-muted-foreground/50 mt-3">
                      These links search each engine for infrastructure sharing the same favicon — a reliable indicator of phishing clones and related threat actors.
                    </p>
                  </div>
                )}

                {/* Shodan detected clone hosts */}
                {(s.faviconShodanMatches as any[] | null)?.length ? (
                  <div className="border border-red-500/20 rounded-xl p-5 bg-red-500/3">
                    <div className="flex items-center gap-2 mb-4">
                      <Server className="w-4 h-4 text-red-400" />
                      <span className="text-sm font-semibold text-red-300">Shodan-Detected Clone Hosts</span>
                      <span className="ml-1 text-xs font-bold bg-red-500/10 border border-red-500/20 text-red-400 px-2 py-0.5 rounded-full">
                        {(s.faviconShodanMatches as any[]).length} host{(s.faviconShodanMatches as any[]).length !== 1 ? "s" : ""}
                      </span>
                    </div>
                    <p className="text-xs text-muted-foreground/70 mb-4">
                      These IPs were found by Shodan using the same favicon hash as <strong className="text-foreground">{s.domain}</strong>. They may be phishing infrastructure, CDN mirror origins, or brand clones.
                    </p>
                    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                      {(s.faviconShodanMatches as any[]).map((m: any, i: number) => (
                        <div key={i} className="flex items-start gap-3 bg-background/60 border border-red-500/20 rounded-lg p-3 hover:border-red-500/40 transition-colors">
                          <Server className="w-3.5 h-3.5 text-red-400 shrink-0 mt-0.5" />
                          <div className="min-w-0 flex-1 space-y-0.5">
                            <p className="text-xs font-mono font-semibold truncate">{m.ip_str ?? m.ip ?? m.hostname ?? "unknown"}</p>
                            {m.hostnames?.length > 0 && <p className="text-[11px] text-muted-foreground truncate">{m.hostnames[0]}</p>}
                            {(m.org || m.isp) && <p className="text-[11px] text-muted-foreground/60 truncate">{m.org ?? m.isp}</p>}
                            {m.port && <p className="text-[11px] text-muted-foreground/50">Port {m.port}</p>}
                          </div>
                          {m.country_code && (
                            <span className="text-[10px] font-bold text-muted-foreground bg-muted px-1.5 py-0.5 rounded-sm shrink-0">{m.country_code}</span>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                ) : (
                  <div className="border border-border rounded-xl p-6 text-center">
                    <Server className="w-8 h-8 text-muted-foreground/30 mx-auto mb-2" />
                    <p className="text-sm text-muted-foreground">No Shodan clone hosts detected</p>
                    <p className="text-xs text-muted-foreground/60 mt-1">
                      Either no hosts share this favicon hash, or a Shodan API key has not been configured.
                    </p>
                  </div>
                )}
              </>
            ) : (
              <div className="flex flex-col items-center justify-center h-64 gap-3">
                <Fingerprint className="w-12 h-12 text-muted-foreground/20" />
                <p className="text-muted-foreground">
                  {s.favihunterStatus === "error"
                    ? `Favicon intelligence unavailable: ${s.favihunterError ?? "unknown error"}`
                    : s.favihunterStatus === "running" || s.favihunterStatus === "pending"
                    ? "Favicon analysis in progress…"
                    : "No favicon found for this domain."}
                </p>
              </div>
            )}
          </div>
        )}

        {/* ── SUBDOMAINS tab ── */}
        {activeTab === "subdomains" && s.status === "done" && (
          <div className="h-full overflow-y-auto">
            <SubdomainsTab subdomains={pipelineSubdomains} pipelineScanId={s.pipelineScanId as number} scanDomain={s.domain} />
          </div>
        )}

        {/* ── TYPOSQUATTING tab ── */}
        {(activeTab === "typosquatting" || s.status !== "done") && results.length > 0 && (
          <div className="flex h-full overflow-hidden mt-0">
            {/* Left sidebar */}
            <div className="w-64 shrink-0 border-r border-border overflow-y-auto p-4 space-y-4 bg-card/50">
              {chartData.length > 0 && (
                <div>
                  <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-3">Permutation Types</p>
                  <div style={{ height: Math.max(200, chartData.length * 28) }}>
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart data={chartData} layout="vertical" margin={{ left: 0, right: 16, top: 0, bottom: 0 }}>
                        <XAxis type="number" hide />
                        <YAxis type="category" dataKey="label" width={80}
                          tick={{ fontSize: 11, fill: "hsl(var(--muted-foreground))" }}
                          tickLine={false} axisLine={false} />
                        <Tooltip
                          cursor={{ fill: "rgba(255,255,255,0.03)" }}
                          contentStyle={{ background: "hsl(var(--card))", border: "1px solid hsl(var(--border))", borderRadius: 8, fontSize: 11 }}
                          formatter={(value: any) => [value, "permutations"]}
                          labelFormatter={(label: string) => label}
                        />
                        <Bar dataKey="count" radius={[0, 3, 3, 0]} maxBarSize={14}>
                          {chartData.map((entry) => (<Cell key={entry.fuzzer} fill={entry.color} />))}
                        </Bar>
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                </div>
              )}

              <div className="border-t border-border" />
              <div>
                <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-3">Filters</p>
                <div className="space-y-1">
                  {([
                    { key: "all",        label: "All results",         count: results.length,        icon: <Eye className="w-3.5 h-3.5" /> },
                    { key: "live",       label: "Live (DNS A)",        count: liveResults.length,    icon: <Server className="w-3.5 h-3.5" /> },
                    { key: "mx",         label: "Has MX",              count: mxResults.length,      icon: <Mail className="w-3.5 h-3.5" /> },
                    { key: "suspicious", label: "Suspicious",          count: suspResults.length,    icon: <AlertTriangle className="w-3.5 h-3.5" /> },
                    { key: "phishing",   label: "Confirmed Phishing",  count: phishResults.length,   icon: <Fish className="w-3.5 h-3.5" /> },
                  ] as const).map(({ key, label, count, icon }) => (
                    <button
                      key={key}
                      onClick={() => { setFilter(key); setPage(0); }}
                      className={cn(
                        "w-full flex items-center gap-2 px-3 py-2 rounded-xl text-xs transition-all",
                        filter === key
                          ? "bg-primary/10 text-primary border border-primary/20"
                          : "text-muted-foreground hover:bg-muted/50",
                      )}
                    >
                      {icon}
                      <span className="flex-1 text-left">{label}</span>
                      <span className={cn(
                        "text-[10px] font-bold px-1.5 py-0.5 rounded-full min-w-[18px] text-center",
                        filter === key ? "bg-primary/20 text-primary" : "bg-muted text-muted-foreground",
                      )}>
                        {count}
                      </span>
                    </button>
                  ))}
                </div>

                <div className="mt-3 border-t border-border pt-3">
                  <p className="text-[10px] text-muted-foreground mb-2">Permutation type</p>
                  <select
                    value={fuzzerFilter}
                    onChange={e => { setFuzzerFilter(e.target.value); setPage(0); }}
                    className="w-full bg-background border border-border rounded-lg px-2 py-1.5 text-xs focus:outline-none"
                  >
                    <option value="all">All types</option>
                    {Array.from(new Set(results.map((r: any) => r.fuzzer))).sort().map((f: string) => (
                      <option key={f} value={f}>{FUZZER_META[f]?.label ?? f}</option>
                    ))}
                  </select>
                </div>
              </div>
            </div>

            {/* Results — registered / unregistered split */}
            <div className="flex-1 min-w-0 flex flex-col overflow-hidden">
              <div className="px-5 py-3 border-b border-border flex items-center gap-3 bg-card/30">
                <Activity className="w-3.5 h-3.5 text-muted-foreground shrink-0" />
                <span className="text-sm font-medium">
                  Domain Permutations
                  <span className="text-muted-foreground font-normal text-xs ml-2">
                    {filtered.length} of {results.length}
                  </span>
                </span>
                <div className="flex-1" />
                <input
                  type="text"
                  placeholder="Search domains…"
                  value={search}
                  onChange={e => { setSearch(e.target.value); setPage(0); }}
                  className="bg-background border border-border rounded-lg px-3 py-1 text-xs focus:outline-none focus:ring-1 focus:ring-primary/40 w-44"
                />
              </div>

              <div className="flex-1 overflow-y-auto">
                {/* ── Registered Domains table ─────────────────────────────── */}
                {(() => {
                  const registered = filtered.filter((r: any) =>
                    r.registrationStatus === "registered" ||
                    r.registrationStatus === "active" ||
                    r.registrationStatus === "parked" ||
                    r.registrationStatus === "protected"  // legacy compat
                  );
                  const unregistered = filtered.filter((r: any) =>
                    !r.registrationStatus ||
                    r.registrationStatus === "unregistered" ||
                    r.registrationStatus === "unresolved"  // legacy compat
                  );

                  function PermRow({ r }: { r: any }) {
                    const fm = FUZZER_META[r.fuzzer];
                    const isExpanded = expandedId === r.id;
                    return (
                      <div>
                        <div
                          className={cn(
                            "grid grid-cols-[28px_1fr_110px_80px_60px_60px_90px_100px] items-center px-5 py-2.5 hover:bg-muted/20 transition-colors cursor-pointer",
                            r.isSuspicious && "bg-orange-500/3",
                            r.isPhishing && "bg-red-500/5",
                          )}
                          onClick={() => setExpandedId(isExpanded ? null : r.id)}
                        >
                          <div className="flex items-center justify-center">
                            {r.isPhishing
                              ? <Fish className="w-3.5 h-3.5 text-red-400" />
                              : r.isSuspicious
                              ? <AlertTriangle className="w-3.5 h-3.5 text-orange-400" />
                              : <CheckCircle2 className="w-3.5 h-3.5 text-muted-foreground/20" />
                            }
                          </div>
                          <div className="flex items-center gap-2 min-w-0 pr-2">
                            <span className="text-sm font-mono truncate">{r.permutation}</span>
                            {isExpanded ? <ChevronUp className="w-3 h-3 text-muted-foreground/40 shrink-0" /> : <ChevronDown className="w-3 h-3 text-muted-foreground/40 shrink-0" />}
                          </div>
                          <div className="flex justify-center">
                            <span className={cn("text-[10px] px-2 py-0.5 rounded-full font-medium", fm ? `${fm.color} ${fm.bg}` : "text-muted-foreground bg-muted")}>
                              {fm?.label ?? r.fuzzer}
                            </span>
                          </div>
                          <div className="flex justify-center">
                            {r.dnsA?.length > 0 ? (
                              <span className="flex items-center gap-1 text-[11px] text-red-400 font-mono font-medium">
                                <Server className="w-2.5 h-2.5 shrink-0" />
                                {r.dnsA[0].length > 11 ? r.dnsA[0].slice(0, 11) + "…" : r.dnsA[0]}
                              </span>
                            ) : <span className="text-xs text-muted-foreground/30">—</span>}
                          </div>
                          <div className="flex justify-center">
                            {r.dnsNs?.length > 0 ? (
                              <span className="text-[10px] text-blue-400 font-medium">NS</span>
                            ) : <span className="text-xs text-muted-foreground/30">—</span>}
                          </div>
                          <div className="flex justify-center">
                            {r.dnsMx?.length > 0 ? (
                              <span className="flex items-center gap-1 text-[11px] text-orange-400 font-medium">
                                <Mail className="w-2.5 h-2.5" /> MX
                              </span>
                            ) : <span className="text-xs text-muted-foreground/30">—</span>}
                          </div>
                          <div className="flex justify-center">
                            {r.vtMalicious > 0 ? (
                              <span className="text-[11px] text-red-400 font-bold">{r.vtMalicious} 🚩</span>
                            ) : r.vtMalicious === 0 ? (
                              <span className="text-[11px] text-green-400/60">clean</span>
                            ) : <span className="text-xs text-muted-foreground/30">—</span>}
                          </div>
                          <div className="px-2">
                            <RiskScoreBar score={r.riskScore} />
                          </div>
                        </div>

                        {isExpanded && (
                          <div className="bg-muted/10 border-t border-border/50 px-8 py-4">
                            <div className="grid grid-cols-2 sm:grid-cols-4 gap-5 text-xs">
                              <div>
                                <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-2">DNS Records</p>
                                <div className="space-y-1">
                                  {r.dnsA?.length > 0 && r.dnsA.map((ip: string) => (
                                    <div key={ip} className="flex items-center gap-1.5">
                                      <Server className="w-3 h-3 text-red-400 shrink-0" />
                                      <span className="font-mono">{ip}</span>
                                      {r.geoCountry && r.dnsA[0] === ip && <span className="text-muted-foreground/60">({r.geoCountry})</span>}
                                    </div>
                                  ))}
                                  {r.dnsNs?.length > 0 && r.dnsNs.slice(0, 2).map((ns: string) => (
                                    <div key={ns} className="flex items-center gap-1.5">
                                      <Globe className="w-3 h-3 text-muted-foreground shrink-0" />
                                      <span className="font-mono text-muted-foreground">{ns}</span>
                                    </div>
                                  ))}
                                  {!r.dnsA?.length && !r.dnsNs?.length && <p className="text-muted-foreground/50 italic">No records</p>}
                                </div>
                              </div>
                              <div>
                                <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-2">RDAP / WHOIS</p>
                                {r.whoisRegistrar || r.whoisCreated ? (
                                  <div className="space-y-1">
                                    {r.whoisRegistrar && <p className="flex items-center gap-1"><Building2 className="w-3 h-3 text-muted-foreground" /> {r.whoisRegistrar.slice(0, 25)}{r.whoisRegistrar.length > 25 ? "…" : ""}</p>}
                                    {r.whoisCreated && <p className="flex items-center gap-1"><Calendar className="w-3 h-3 text-muted-foreground" /> Created: {r.whoisCreated?.slice(0, 10)}</p>}
                                    {r.whoisCountry && <p className="flex items-center gap-1"><MapPin className="w-3 h-3 text-muted-foreground" /> {r.whoisCountry}</p>}
                                    {r.whoisAbuseContact && <p className="flex items-center gap-1 break-all"><Mail className="w-3 h-3 text-muted-foreground shrink-0" /><a href={`mailto:${r.whoisAbuseContact}`} className="text-primary hover:underline">{r.whoisAbuseContact}</a></p>}
                                    {r.whoisAgeDays !== null && r.whoisAgeDays !== undefined && (
                                      <p className={cn("flex items-center gap-1", r.whoisAgeDays < 90 ? "text-red-400" : "")}>
                                        <Info className="w-3 h-3 text-muted-foreground" />
                                        {r.whoisAgeDays < 90 ? `⚠ New domain (${r.whoisAgeDays}d old)` : `${r.whoisAgeDays}d old`}
                                      </p>
                                    )}
                                  </div>
                                ) : <p className="text-muted-foreground/50 italic">Not resolved</p>}
                              </div>
                              <div>
                                <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-2">GeoIP</p>
                                {r.geoCountry || r.geoOrg ? (
                                  <div className="space-y-1">
                                    {r.geoCountry && <p className="flex items-center gap-1"><MapPin className="w-3 h-3 text-muted-foreground" /> {r.geoCity ? `${r.geoCity}, ` : ""}{r.geoCountry}</p>}
                                    {r.geoAsn && <p className="flex items-center gap-1"><Globe className="w-3 h-3 text-muted-foreground" /> {r.geoAsn}</p>}
                                    {r.geoOrg && <p className="flex items-center gap-1"><Building2 className="w-3 h-3 text-muted-foreground" /> {r.geoOrg.slice(0, 25)}{r.geoOrg.length > 25 ? "…" : ""}</p>}
                                  </div>
                                ) : <p className="text-muted-foreground/50 italic">Not resolved</p>}
                              </div>
                              <div>
                                <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-2">Threat Intel</p>
                                <div className="space-y-1.5">
                                  {r.isPhishing && <div className="flex items-center gap-1.5 text-red-400"><Fish className="w-3 h-3 shrink-0" /><span>Confirmed phishing ({r.phishingSource})</span></div>}
                                  {r.vtMalicious !== null && r.vtMalicious !== undefined && (
                                    <div className={cn("flex items-center gap-1.5", r.vtMalicious > 0 ? "text-red-400" : "text-green-400/70")}>
                                      <ShieldAlert className="w-3 h-3 shrink-0" />
                                      VT: {r.vtMalicious} malicious / {r.vtSuspicious ?? 0} suspicious
                                    </div>
                                  )}
                                  {r.vtPermalink && (
                                    <a href={r.vtPermalink} target="_blank" rel="noopener noreferrer" className="flex items-center gap-1 text-muted-foreground hover:text-foreground transition-colors">
                                      <ExternalLink className="w-3 h-3" /> VirusTotal report
                                    </a>
                                  )}
                                  {!r.isPhishing && (r.vtMalicious === null || r.vtMalicious === undefined) && <p className="text-muted-foreground/50 italic">No threat data</p>}
                                </div>
                              </div>
                            </div>
                            {/* Screenshot (captured for score ≥ 70) */}
                            {r.screenshot && (
                              <div className="mt-4 pt-4 border-t border-border/50">
                                <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-2 flex items-center gap-1.5">
                                  <Eye className="w-3 h-3" /> Live Screenshot
                                  <span className="text-[9px] text-orange-400/70">(captured at scan time)</span>
                                </p>
                                <div className="rounded-lg overflow-hidden border border-border max-w-md">
                                  <img
                                    src={`data:image/png;base64,${r.screenshot}`}
                                    alt={`Screenshot of ${r.permutation}`}
                                    className="w-full object-cover"
                                    loading="lazy"
                                  />
                                </div>
                                <p className="text-[10px] text-muted-foreground/50 mt-1.5">
                                  {r.permutation}
                                </p>
                              </div>
                            )}
                          </div>
                        )}
                      </div>
                    );
                  }

                  const REG_HEADER = (
                    <div className="grid grid-cols-[28px_1fr_110px_80px_60px_60px_90px_100px] items-center px-5 py-2 border-b border-border bg-muted/20 text-[10px] text-muted-foreground uppercase tracking-wider">
                      <span />
                      <span>Domain</span>
                      <span className="text-center">Type</span>
                      <span className="text-center">A Records</span>
                      <span className="text-center">NS</span>
                      <span className="text-center">MX</span>
                      <span className="text-center">VT</span>
                      <span className="text-center">Risk</span>
                    </div>
                  );

                  const activeThreats = registered.filter((r: any) => r.riskScore >= 70);
                  const underWatch = registered.filter((r: any) => r.riskScore >= 40 && r.riskScore < 70);
                  const lowRisk = registered.filter((r: any) => r.riskScore < 40);

                  return (
                    <div className="divide-y divide-border">
                      {/* ── Active Threats (score ≥ 70) ── */}
                      <div>
                        <div className="px-5 py-2.5 bg-red-500/5 border-b border-red-500/20 flex items-center gap-2">
                          <div className="w-2 h-2 rounded-full bg-red-400 shrink-0" />
                          <span className="text-xs font-semibold text-red-400 uppercase tracking-wider">
                            Active Threats
                          </span>
                          <span className="text-[10px] text-red-400/60 bg-red-500/10 px-1.5 py-0.5 rounded-full font-bold">
                            {activeThreats.length}
                          </span>
                          <span className="text-[10px] text-muted-foreground ml-1">— risk score ≥ 70, likely active abuse or phishing</span>
                        </div>
                        {activeThreats.length > 0 ? (
                          <>
                            {REG_HEADER}
                            <div className="divide-y divide-border">
                              {activeThreats.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE).map((r: any) => <PermRow key={r.id} r={r} />)}
                            </div>
                          </>
                        ) : (
                          <div className="flex items-center gap-2 px-5 py-4 text-sm text-green-400/70">
                            <CheckCircle2 className="w-4 h-4 shrink-0" /> No active threats found — good signal
                          </div>
                        )}
                      </div>

                      {/* ── Under Watch (score 40-69) ── */}
                      {underWatch.length > 0 && (
                        <div>
                          <div className="px-5 py-2.5 bg-orange-500/5 border-b border-orange-500/20 flex items-center gap-2">
                            <div className="w-2 h-2 rounded-full bg-orange-400 shrink-0" />
                            <span className="text-xs font-semibold text-orange-400 uppercase tracking-wider">
                              Under Watch
                            </span>
                            <span className="text-[10px] text-orange-400/60 bg-orange-500/10 px-1.5 py-0.5 rounded-full font-bold">
                              {underWatch.length}
                            </span>
                            <span className="text-[10px] text-muted-foreground ml-1">— risk score 40-69, suspicious but not confirmed</span>
                          </div>
                          {REG_HEADER}
                          <div className="divide-y divide-border">
                            {underWatch.map((r: any) => <PermRow key={r.id} r={r} />)}
                          </div>
                        </div>
                      )}

                      {/* ── Registered / Low Risk ── */}
                      {lowRisk.length > 0 && (
                        <div>
                          <div className="px-5 py-2.5 bg-muted/20 border-b border-border flex items-center gap-2">
                            <div className="w-2 h-2 rounded-full bg-muted-foreground/40 shrink-0" />
                            <span className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                              Registered / Low Risk
                            </span>
                            <span className="text-[10px] text-muted-foreground/60 bg-muted px-1.5 py-0.5 rounded-full font-bold">
                              {lowRisk.length}
                            </span>
                            <span className="text-[10px] text-muted-foreground ml-1">— registered but below suspicion threshold</span>
                          </div>
                          {REG_HEADER}
                          <div className="divide-y divide-border">
                            {lowRisk.map((r: any) => <PermRow key={r.id} r={r} />)}
                          </div>
                        </div>
                      )}

                      {registered.length === 0 && (
                        <div className="flex items-center gap-2 px-5 py-4 text-sm text-green-400/70">
                          <CheckCircle2 className="w-4 h-4 shrink-0" /> No registered permutations found — good signal
                        </div>
                      )}

                      {/* ── Unregistered Domains ── */}
                      <div>
                        <div className="px-5 py-2.5 bg-muted/30 border-b border-border flex items-center gap-2">
                          <div className="w-2 h-2 rounded-full bg-muted-foreground/40 shrink-0" />
                          <span className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                            Unregistered / Unresolved Domains
                          </span>
                          <span className="text-[10px] text-muted-foreground/60 bg-muted px-1.5 py-0.5 rounded-full font-bold">
                            {unregistered.length}
                          </span>
                          <span className="text-[10px] text-muted-foreground ml-1">— available to register; monitor for future squatting</span>
                        </div>
                        {unregistered.length > 0 ? (
                          <>
                            <div className="grid grid-cols-[28px_1fr_110px_80px_60px_60px] items-center px-5 py-2 border-b border-border bg-muted/10 text-[10px] text-muted-foreground uppercase tracking-wider">
                              <span /><span>Domain</span>
                              <span className="text-center">Type</span>
                              <span className="text-center">A Records</span>
                              <span className="text-center">NS</span>
                              <span className="text-center">MX</span>
                            </div>
                            <div className="divide-y divide-border">
                              {unregistered.slice(0, 100).map((r: any) => {
                                const fm = FUZZER_META[r.fuzzer];
                                return (
                                  <div key={r.id} className="grid grid-cols-[28px_1fr_110px_80px_60px_60px] items-center px-5 py-2 hover:bg-muted/10 transition-colors">
                                    <span />
                                    <span className="text-sm font-mono text-muted-foreground truncate">{r.permutation}</span>
                                    <div className="flex justify-center">
                                      <span className={cn("text-[10px] px-2 py-0.5 rounded-full font-medium", fm ? `${fm.color} ${fm.bg}` : "text-muted-foreground bg-muted opacity-60")}>
                                        {fm?.label ?? r.fuzzer}
                                      </span>
                                    </div>
                                    <div className="flex justify-center">
                                      {r.dnsA?.length > 0 ? <span className="text-[11px] text-red-400 font-mono">{r.dnsA[0]?.slice(0, 11)}</span> : <span className="text-xs text-muted-foreground/20">—</span>}
                                    </div>
                                    <div className="flex justify-center">
                                      {r.dnsNs?.length > 0 ? <span className="text-[10px] text-blue-400/60">NS</span> : <span className="text-xs text-muted-foreground/20">—</span>}
                                    </div>
                                    <div className="flex justify-center">
                                      {r.dnsMx?.length > 0 ? <span className="text-[11px] text-orange-400/60">MX</span> : <span className="text-xs text-muted-foreground/20">—</span>}
                                    </div>
                                  </div>
                                );
                              })}
                            </div>
                          </>
                        ) : (
                          <div className="px-5 py-4 text-sm text-muted-foreground/60 italic">No unregistered permutations.</div>
                        )}
                      </div>
                    </div>
                  );
                })()}

                {filtered.length === 0 && (
                  <div className="flex flex-col items-center justify-center h-32 text-center">
                    <Globe className="w-6 h-6 text-muted-foreground/20 mb-2" />
                    <p className="text-sm text-muted-foreground">No results match the current filters</p>
                  </div>
                )}

              </div>

              {totalPages > 1 && (
                <div className="flex items-center justify-between px-5 py-3 border-t border-border bg-card/30">
                  <span className="text-xs text-muted-foreground">
                    Page {page + 1} of {totalPages} (registered domains)
                  </span>
                  <div className="flex items-center gap-1">
                    <Button variant="outline" size="sm" onClick={() => setPage(p => Math.max(0, p - 1))} disabled={page === 0} className="h-7 text-xs">
                      Previous
                    </Button>
                    <span className="text-xs text-muted-foreground px-3">{page + 1} / {totalPages}</span>
                    <Button variant="outline" size="sm" onClick={() => setPage(p => Math.min(totalPages - 1, p + 1))} disabled={page >= totalPages - 1} className="h-7 text-xs">
                      Next
                    </Button>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Empty state for typosquatting tab */}
        {activeTab === "typosquatting" && results.length === 0 && s.status === "done" && (
          <div className="flex flex-col items-center justify-center h-64 text-center">
            <Globe className="w-8 h-8 text-green-400/40 mb-3" />
            <p className="text-base font-semibold text-green-400">No permutations found</p>
            <p className="text-sm text-muted-foreground">No domain permutations were generated for this scan.</p>
          </div>
        )}
      </div>
    </div>
  );
}
