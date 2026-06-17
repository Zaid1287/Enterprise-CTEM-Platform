import { useState, useEffect, useRef, useCallback } from "react";
import { useLocation } from "wouter";
import { Search, X, Server, Bug, Radar, Loader2, Shield, TrendingUp } from "lucide-react";
import { getToken } from "@/lib/auth";

interface AssetResult {
  _type: "asset";
  id: number;
  name: string;
  type: string;
  value: string;
  riskLevel: string;
  rank: number;
}

interface FindingResult {
  _type: "finding";
  id: number;
  title: string;
  severity: string;
  status: string;
  cve: string | null;
  assetId: number;
  rank: number;
}

interface ScanResult {
  _type: "scan";
  id: number;
  name: string;
  type: string;
  status: string;
  createdAt: string;
  rank: number;
}

type SearchResult = AssetResult | FindingResult | ScanResult;

interface SearchResponse {
  assets: AssetResult[];
  findings: FindingResult[];
  scans: ScanResult[];
  total: number;
  query: string;
}

const SEVERITY_COLOR: Record<string, string> = {
  critical: "text-red-400 bg-red-500/10",
  high: "text-orange-400 bg-orange-500/10",
  medium: "text-yellow-400 bg-yellow-500/10",
  low: "text-green-400 bg-green-500/10",
};

const RISK_COLOR: Record<string, string> = {
  critical: "text-red-400",
  high: "text-orange-400",
  medium: "text-yellow-400",
  low: "text-green-400",
};

export function GlobalSearch() {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<SearchResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [selected, setSelected] = useState(0);
  const [, navigate] = useLocation();
  const inputRef = useRef<HTMLInputElement>(null);
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const flatResults = results
    ? ([...results.assets, ...results.findings, ...results.scans] as SearchResult[])
    : [];

  const search = useCallback(async (q: string) => {
    if (q.length < 2) { setResults(null); return; }
    setLoading(true);
    try {
      const base = import.meta.env.BASE_URL.replace(/\/$/, "");
      const token = getToken();
      const res = await fetch(`${base}/api/search?q=${encodeURIComponent(q)}&limit=15`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (res.ok) {
        const data = await res.json() as SearchResponse;
        setResults(data);
        setSelected(0);
      }
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (debounceRef.current) clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(() => search(query), 250);
    return () => { if (debounceRef.current) clearTimeout(debounceRef.current); };
  }, [query, search]);

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault();
        setOpen((o) => !o);
      }
      if (e.key === "Escape") setOpen(false);
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, []);

  useEffect(() => {
    if (open) {
      setTimeout(() => inputRef.current?.focus(), 50);
    } else {
      setQuery("");
      setResults(null);
    }
  }, [open]);

  const handleSelect = (item: SearchResult) => {
    setOpen(false);
    if (item._type === "asset") navigate(`/assets/${item.id}`);
    else if (item._type === "finding") navigate(`/findings/${item.id}`);
    else if (item._type === "scan") navigate(`/scan-reports/${item.id}`);
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "ArrowDown") { e.preventDefault(); setSelected((s) => Math.min(s + 1, flatResults.length - 1)); }
    else if (e.key === "ArrowUp") { e.preventDefault(); setSelected((s) => Math.max(s - 1, 0)); }
    else if (e.key === "Enter" && flatResults[selected]) handleSelect(flatResults[selected]);
  };

  return (
    <>
      <button
        onClick={() => setOpen(true)}
        className="flex items-center gap-2 px-3 h-8 rounded-md bg-muted/50 border border-border/50 text-muted-foreground text-sm hover:bg-muted transition-colors"
      >
        <Search className="w-3.5 h-3.5" />
        <span className="hidden sm:inline">Search…</span>
        <kbd className="hidden sm:inline-flex items-center gap-0.5 px-1.5 h-5 text-[10px] font-mono bg-background/80 border border-border/40 rounded text-muted-foreground/70">
          ⌘K
        </kbd>
      </button>

      {open && (
        <div className="fixed inset-0 z-50 flex items-start justify-center pt-20 px-4" onClick={() => setOpen(false)}>
          <div
            className="relative w-full max-w-xl bg-background border border-border rounded-xl shadow-2xl overflow-hidden"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center gap-3 px-4 py-3 border-b border-border">
              {loading ? <Loader2 className="w-4 h-4 text-muted-foreground animate-spin shrink-0" /> : <Search className="w-4 h-4 text-muted-foreground shrink-0" />}
              <input
                ref={inputRef}
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                onKeyDown={handleKeyDown}
                placeholder="Search assets, findings, scans…"
                className="flex-1 bg-transparent text-sm outline-none placeholder:text-muted-foreground/50"
              />
              {query && (
                <button onClick={() => setQuery("")}>
                  <X className="w-4 h-4 text-muted-foreground hover:text-foreground" />
                </button>
              )}
            </div>

            <div className="max-h-[420px] overflow-y-auto">
              {!query && (
                <div className="px-4 py-8 text-center text-sm text-muted-foreground">
                  Type to search across assets, findings, and scans
                </div>
              )}

              {query && results && results.total === 0 && !loading && (
                <div className="px-4 py-8 text-center text-sm text-muted-foreground">
                  No results for <span className="font-medium text-foreground">"{query}"</span>
                </div>
              )}

              {results && results.assets.length > 0 && (
                <div>
                  <div className="px-4 py-1.5 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground/60 bg-muted/30">
                    Assets
                  </div>
                  {results.assets.map((item, i) => {
                    const globalIdx = i;
                    return (
                      <button
                        key={`asset-${item.id}`}
                        onClick={() => handleSelect(item)}
                        className={`w-full flex items-center gap-3 px-4 py-2.5 text-left hover:bg-muted/50 transition-colors ${selected === globalIdx ? "bg-muted/50" : ""}`}
                      >
                        <div className="w-7 h-7 rounded-md bg-blue-500/10 border border-blue-500/20 flex items-center justify-center shrink-0">
                          <Server className="w-3.5 h-3.5 text-blue-400" />
                        </div>
                        <div className="flex-1 min-w-0">
                          <p className="text-sm font-medium truncate">{item.name}</p>
                          <p className="text-xs text-muted-foreground truncate">{item.value} · {item.type}</p>
                        </div>
                        <span className={`text-[10px] font-medium capitalize ${RISK_COLOR[item.riskLevel] ?? "text-muted-foreground"}`}>
                          {item.riskLevel}
                        </span>
                      </button>
                    );
                  })}
                </div>
              )}

              {results && results.findings.length > 0 && (
                <div>
                  <div className="px-4 py-1.5 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground/60 bg-muted/30">
                    Findings
                  </div>
                  {results.findings.map((item, i) => {
                    const globalIdx = (results?.assets.length ?? 0) + i;
                    return (
                      <button
                        key={`finding-${item.id}`}
                        onClick={() => handleSelect(item)}
                        className={`w-full flex items-center gap-3 px-4 py-2.5 text-left hover:bg-muted/50 transition-colors ${selected === globalIdx ? "bg-muted/50" : ""}`}
                      >
                        <div className="w-7 h-7 rounded-md bg-red-500/10 border border-red-500/20 flex items-center justify-center shrink-0">
                          <Bug className="w-3.5 h-3.5 text-red-400" />
                        </div>
                        <div className="flex-1 min-w-0">
                          <p className="text-sm font-medium truncate">{item.title}</p>
                          <p className="text-xs text-muted-foreground truncate">
                            {item.cve ?? "No CVE"} · Asset #{item.assetId}
                          </p>
                        </div>
                        <span className={`text-[10px] font-medium px-1.5 py-0.5 rounded capitalize ${SEVERITY_COLOR[item.severity] ?? ""}`}>
                          {item.severity}
                        </span>
                      </button>
                    );
                  })}
                </div>
              )}

              {results && results.scans.length > 0 && (
                <div>
                  <div className="px-4 py-1.5 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground/60 bg-muted/30">
                    Scans
                  </div>
                  {results.scans.map((item, i) => {
                    const globalIdx = (results?.assets.length ?? 0) + (results?.findings.length ?? 0) + i;
                    return (
                      <button
                        key={`scan-${item.id}`}
                        onClick={() => handleSelect(item)}
                        className={`w-full flex items-center gap-3 px-4 py-2.5 text-left hover:bg-muted/50 transition-colors ${selected === globalIdx ? "bg-muted/50" : ""}`}
                      >
                        <div className="w-7 h-7 rounded-md bg-violet-500/10 border border-violet-500/20 flex items-center justify-center shrink-0">
                          <Radar className="w-3.5 h-3.5 text-violet-400" />
                        </div>
                        <div className="flex-1 min-w-0">
                          <p className="text-sm font-medium truncate">{item.name}</p>
                          <p className="text-xs text-muted-foreground truncate">
                            {new Date(item.createdAt).toLocaleDateString()} · {item.type}
                          </p>
                        </div>
                        <span className={`text-[10px] font-medium capitalize px-1.5 py-0.5 rounded ${item.status === "completed" ? "text-green-400 bg-green-500/10" : item.status === "running" ? "text-blue-400 bg-blue-500/10" : "text-muted-foreground bg-muted"}`}>
                          {item.status}
                        </span>
                      </button>
                    );
                  })}
                </div>
              )}
            </div>

            <div className="flex items-center gap-4 px-4 py-2 border-t border-border bg-muted/20 text-[10px] text-muted-foreground/60">
              <span><kbd className="font-mono">↑↓</kbd> navigate</span>
              <span><kbd className="font-mono">↵</kbd> select</span>
              <span><kbd className="font-mono">Esc</kbd> close</span>
              {results && <span className="ml-auto">{results.total} results</span>}
            </div>
          </div>
        </div>
      )}
    </>
  );
}
