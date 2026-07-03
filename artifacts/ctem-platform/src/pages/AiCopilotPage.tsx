import { useState, useEffect, useRef, useCallback } from "react";
import { useLocation, useSearch } from "wouter";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import {
  useListFindings, useListComplianceControls, useListScans,
  getListFindingsQueryKey, getListComplianceControlsQueryKey, getListScansQueryKey,
} from "@workspace/api-client-react";
import { useAuth } from "@/hooks/useAuth";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectGroup, SelectItem, SelectLabel, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Brain, Zap, FileText, ShieldCheck, AlertTriangle, Sparkles, Clock,
  ChevronRight, Send, RotateCcw, MessageSquare, Activity, Search,
  BarChart3, Shield, ExternalLink, Trash2, User, Bot,
} from "lucide-react";
import { cn } from "@/lib/utils";

const BASE = import.meta.env.BASE_URL.replace(/\/$/, "");

// ── Types ────────────────────────────────────────────────────────────────────
interface ProviderInfo { id: string; name: string; model: string; source: string; }
interface ChatMessage { role: "user" | "assistant"; content: string; timestamp: string; usage?: { totalTokens: number }; }
interface CacheEntry { content: string; timestamp: string; model: string; usage?: { totalTokens: number }; }
interface StreamResult { text: string; model: string; usage?: { totalTokens: number }; noKey?: boolean; }

const PROVIDER_NAMES: Record<string, string> = {
  openai: "OpenAI", anthropic: "Anthropic", gemini: "Google Gemini",
  openrouter: "OpenRouter", ollama: "Ollama",
};

const PROVIDER_COLORS: Record<string, string> = {
  openai: "text-green-400", anthropic: "text-orange-400",
  gemini: "text-blue-400", openrouter: "text-purple-400", ollama: "text-teal-400",
};

// ── localStorage cache ────────────────────────────────────────────────────────
function cacheKey(action: string, id: string | number) { return `ai-copilot:${action}:${id}`; }
function readCache(action: string, id: string | number): CacheEntry | null {
  try { const v = localStorage.getItem(cacheKey(action, id)); return v ? JSON.parse(v) : null; } catch { return null; }
}
function writeCache(action: string, id: string | number, entry: CacheEntry) {
  try { localStorage.setItem(cacheKey(action, id), JSON.stringify(entry)); } catch { /* quota */ }
}
function chatCacheKey(findingId?: string) { return `ai-chat:${findingId ?? "global"}`; }
function readChatCache(findingId?: string): ChatMessage[] {
  try { const v = localStorage.getItem(chatCacheKey(findingId)); return v ? JSON.parse(v) : []; } catch { return []; }
}
function writeChatCache(findingId: string | undefined, msgs: ChatMessage[]) {
  try { localStorage.setItem(chatCacheKey(findingId), JSON.stringify(msgs.slice(-40))); } catch { /* quota */ }
}

// ── Streaming hook ────────────────────────────────────────────────────────────
function useStream() {
  const [text, setText] = useState("");
  const [streaming, setStreaming] = useState(false);
  const [provider, setProvider] = useState<string | null>(null);
  const [usage, setUsage] = useState<{ totalTokens: number } | null>(null);
  const [noKey, setNoKey] = useState(false);
  const abortRef = useRef(false);

  const run = useCallback(async (body: object): Promise<StreamResult> => {
    abortRef.current = false;
    setText(""); setStreaming(true); setProvider(null); setUsage(null); setNoKey(false);
    const token = sessionStorage.getItem("ctem_token") ?? "";
    let accumulated = "";
    let finalModel = "template";
    let finalUsage: { totalTokens: number } | undefined;
    let isNoKey = false;

    try {
      const resp = await fetch(`${BASE}/api/ai/stream`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
        body: JSON.stringify(body),
      });

      if (!resp.ok || !resp.body) throw new Error(`HTTP ${resp.status}`);

      const reader = resp.body.getReader();
      const decoder = new TextDecoder();
      let buf = "";

      while (true) {
        if (abortRef.current) { reader.cancel(); break; }
        const { done, value } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        const lines = buf.split("\n");
        buf = lines.pop() ?? "";
        for (const line of lines) {
          if (!line.startsWith("data: ")) continue;
          try {
            const d = JSON.parse(line.slice(6));
            if (d.provider) { setProvider(d.provider); finalModel = d.provider + "/" + d.model; }
            if (d.noKey) { setNoKey(true); isNoKey = true; }
            if (d.text) { accumulated += d.text; setText(prev => prev + d.text); }
            if (d.usage) { finalUsage = { totalTokens: d.usage.totalTokens ?? 0 }; setUsage(finalUsage); }
            if (d.model && d.done) finalModel = d.model;
          } catch { /* ignore */ }
        }
      }
    } catch (err) {
      setText(prev => prev || "Error generating response. Please try again.");
    } finally {
      setStreaming(false);
    }

    return { text: accumulated, model: finalModel, usage: finalUsage, noKey: isNoKey };
  }, []);

  const cancel = () => { abortRef.current = true; };
  const reset = () => { setText(""); setProvider(null); setUsage(null); setNoKey(false); };

  return { text, streaming, provider, usage, noKey, run, cancel, reset };
}

// ── Markdown renderer ─────────────────────────────────────────────────────────
export function AiMarkdown({ content }: { content: string }) {
  return (
    <ReactMarkdown
      remarkPlugins={[remarkGfm]}
      components={{
        h2: ({ children }) => <h2 className="text-sm font-bold mt-4 mb-2 text-foreground">{children}</h2>,
        h3: ({ children }) => <h3 className="text-xs font-semibold mt-3 mb-1.5 text-foreground/90">{children}</h3>,
        p: ({ children }) => <p className="text-xs text-muted-foreground mb-2 leading-relaxed">{children}</p>,
        ul: ({ children }) => <ul className="list-disc pl-5 space-y-0.5 mb-2">{children}</ul>,
        ol: ({ children }) => <ol className="list-decimal pl-5 space-y-0.5 mb-2">{children}</ol>,
        li: ({ children }) => <li className="text-xs text-muted-foreground">{children}</li>,
        strong: ({ children }) => <strong className="font-semibold text-foreground">{children}</strong>,
        code: ({ children }) => <code className="font-mono text-[10px] bg-muted/60 px-1 py-0.5 rounded text-primary">{children}</code>,
        blockquote: ({ children }) => <blockquote className="border-l-2 border-primary/40 pl-3 my-2 text-muted-foreground italic text-xs">{children}</blockquote>,
        table: ({ children }) => <div className="overflow-x-auto my-2"><table className="text-[11px] w-full border-collapse">{children}</table></div>,
        thead: ({ children }) => <thead className="bg-muted/40">{children}</thead>,
        th: ({ children }) => <th className="px-2 py-1 text-left font-semibold text-foreground border border-border/40">{children}</th>,
        td: ({ children }) => <td className="px-2 py-1 text-muted-foreground border border-border/40">{children}</td>,
        a: ({ href, children }) => <a href={href} target="_blank" rel="noopener noreferrer" className="text-primary underline underline-offset-2 text-xs">{children}</a>,
        hr: () => <hr className="border-border/40 my-3" />,
      }}
    >
      {content}
    </ReactMarkdown>
  );
}

// ── AI Output box ─────────────────────────────────────────────────────────────
function AiOutput({
  text, streaming, noKey, model, usage, generatedAt, cacheHit,
}: {
  text: string; streaming: boolean; noKey?: boolean; model?: string;
  usage?: { totalTokens: number } | null; generatedAt?: string; cacheHit?: boolean;
}) {
  if (!text && !streaming) {
    return <p className="text-xs text-muted-foreground/60 italic">Select options above and click generate.</p>;
  }
  return (
    <div className="space-y-2">
      {noKey && (
        <div className="flex items-center gap-2 text-[10px] text-amber-400/80 bg-amber-500/10 border border-amber-500/20 rounded-lg px-2.5 py-1.5 mb-2">
          <AlertTriangle className="w-3 h-3 shrink-0" />
          No AI provider configured — showing template response.
          <a href="/settings/account" className="underline ml-auto shrink-0">Add API key →</a>
        </div>
      )}
      <AiMarkdown content={text} />
      {streaming && <span className="inline-block w-1.5 h-4 bg-primary/70 animate-pulse ml-0.5 rounded-sm" />}
      {(model || usage || generatedAt || cacheHit) && !streaming && (
        <div className="flex flex-wrap items-center gap-2 pt-1 text-[10px] text-muted-foreground/40 border-t border-border/20">
          {cacheHit && <span className="text-amber-400/60">♻ cached</span>}
          {model && <span className={cn(model.startsWith("template") ? "text-amber-400/60" : "text-green-400/60")}>⚡ {model}</span>}
          {usage && <span>~{usage.totalTokens.toLocaleString()} tokens</span>}
          {generatedAt && <span className="ml-auto flex items-center gap-1"><Clock className="w-2.5 h-2.5" />{new Date(generatedAt).toLocaleTimeString()}</span>}
        </div>
      )}
    </div>
  );
}

// ── Provider badge ────────────────────────────────────────────────────────────
function ProviderBadge({ providers, selected, onSelect }: {
  providers: ProviderInfo[]; selected: string; onSelect: (id: string) => void;
}) {
  if (!providers.length) return null;
  if (providers.length === 1) {
    const p = providers[0];
    return (
      <div className={cn("flex items-center gap-1 text-[10px] px-2 py-0.5 rounded-full border font-medium", PROVIDER_COLORS[p.id] ?? "text-muted-foreground", "border-current/30 bg-current/5")}>
        <span className="w-1.5 h-1.5 rounded-full bg-current animate-pulse" />
        {p.name} · {p.model}
      </div>
    );
  }
  return (
    <Select value={selected} onValueChange={onSelect}>
      <SelectTrigger className="h-7 text-[11px] w-auto gap-1.5 px-2 border-border/50">
        <SelectValue placeholder="Select AI provider" />
      </SelectTrigger>
      <SelectContent>
        {providers.map(p => (
          <SelectItem key={p.id} value={p.id} className="text-xs">
            <span className={cn("font-medium", PROVIDER_COLORS[p.id])}>{p.name}</span>
            <span className="text-muted-foreground ml-1">· {p.model}</span>
            {p.source === "user" && <span className="text-muted-foreground/50 ml-1">(your key)</span>}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}

// ── No-key banner ─────────────────────────────────────────────────────────────
function NoKeyBanner() {
  return (
    <div className="flex items-start gap-3 p-3.5 rounded-xl bg-amber-500/10 border border-amber-500/30">
      <AlertTriangle className="w-4 h-4 text-amber-400 mt-0.5 shrink-0" />
      <div className="space-y-1 flex-1 min-w-0">
        <p className="text-xs font-medium text-amber-300">No AI provider configured</p>
        <p className="text-[11px] text-amber-400/80 leading-relaxed">
          All functions work in template mode. For real AI responses, add at least one API key.
        </p>
        <a href="/settings/account" className="inline-flex items-center gap-1 text-[11px] text-amber-400 underline underline-offset-2 mt-1">
          Go to Account Settings → AI Settings <ExternalLink className="w-2.5 h-2.5" />
        </a>
      </div>
    </div>
  );
}

// ── Session token counter ─────────────────────────────────────────────────────
function TokenCounter({ total, requests }: { total: number; requests: number }) {
  if (!total && !requests) return null;
  return (
    <div className="flex items-center gap-2 text-[10px] text-muted-foreground/50 px-1">
      <Activity className="w-2.5 h-2.5" />
      <span>Session: {total.toLocaleString()} tokens · {requests} requests</span>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
export default function AiCopilotPage() {
  const [, navigate] = useLocation();
  const searchStr = useSearch();
  const { user } = useAuth();

  // Parse URL params for deeplink: /ai-copilot?findingId=5&action=explain
  const urlParams = new URLSearchParams(searchStr);
  const urlFindingId = urlParams.get("findingId") ?? "";
  const urlAction   = urlParams.get("action") ?? "explain";
  const urlScanId   = urlParams.get("scanId") ?? "";
  const urlAssetId  = urlParams.get("assetId") ?? "";

  const [activeTab, setActiveTab] = useState(urlAction === "chat" ? "chat" : urlAction === "remediation" ? "remediation" : urlAction === "executive" ? "executive" : urlAction === "compliance" ? "compliance" : urlAction === "risk" ? "risk" : urlAction === "scan" ? "scan" : "explain");
  const [providers, setProviders] = useState<ProviderInfo[]>([]);
  const [selectedProvider, setSelectedProvider] = useState("");
  const [providersLoaded, setProvidersLoaded] = useState(false);

  // Session token tracking
  const [sessionTokens, setSessionTokens] = useState(0);
  const [sessionRequests, setSessionRequests] = useState(0);
  const addTokens = (n: number) => { setSessionTokens(p => p + n); setSessionRequests(p => p + 1); };

  // ── Data
  const { data: findings } = useListFindings({} as any, { query: { queryKey: getListFindingsQueryKey({} as any) } });
  const { data: controls } = useListComplianceControls({} as any, { query: { queryKey: getListComplianceControlsQueryKey({} as any) } });
  const { data: scans }    = useListScans({} as any, { query: { queryKey: getListScansQueryKey({} as any) } });

  const findingList  = (findings as any[] ?? []).sort((a: any, b: any) => { const o: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }; return (o[a.severity] ?? 5) - (o[b.severity] ?? 5); });
  const controlList  = (controls as any[] ?? []);
  const scanList     = (scans as any[] ?? []).filter((s: any) => s.status === "completed");

  // ── Load providers
  useEffect(() => {
    const token = sessionStorage.getItem("ctem_token") ?? "";
    fetch(`${BASE}/api/ai/providers`, { headers: { Authorization: `Bearer ${token}` } })
      .then(r => r.json())
      .then((d: any) => {
        setProviders(d.providers ?? []);
        if (d.providers?.length) setSelectedProvider(d.providers[0].id);
        setProvidersLoaded(true);
      })
      .catch(() => setProvidersLoaded(true));
  }, []);

  // ── Compliance search
  const [controlSearch, setControlSearch] = useState("");
  const filteredControls = controlSearch
    ? controlList.filter((c: any) =>
        c.controlId?.toLowerCase().includes(controlSearch.toLowerCase()) ||
        c.title?.toLowerCase().includes(controlSearch.toLowerCase()) ||
        c.frameworkName?.toLowerCase().includes(controlSearch.toLowerCase()))
    : controlList;
  const groupedControls = filteredControls.reduce((acc: Record<string, any[]>, c: any) => {
    const fw = c.frameworkName ?? "Other";
    if (!acc[fw]) acc[fw] = [];
    acc[fw].push(c);
    return acc;
  }, {});

  // ── Tab state
  const [selectedFinding, setSelectedFinding] = useState(urlFindingId);
  const [selectedControl, setSelectedControl] = useState("");
  const [selectedScan, setSelectedScan]       = useState(urlScanId);
  const [selectedAsset, setSelectedAsset]     = useState(urlAssetId);

  // ── Streams (one per tab)
  const explainStream     = useStream();
  const remediationStream = useStream();
  const execStream        = useStream();
  const complianceStream  = useStream();
  const riskStream        = useStream();
  const scanStream        = useStream();

  // ── Cache state (track cache hits)
  const [cacheHits, setCacheHits] = useState<Record<string, string>>({});

  // ── Chat state
  const [chatInput, setChatInput] = useState("");
  const [chatMessages, setChatMessages] = useState<ChatMessage[]>([]);
  const [chatStreaming, setChatStreaming] = useState(false);
  const [chatStreamText, setChatStreamText] = useState("");
  const chatBottomRef = useRef<HTMLDivElement>(null);

  // Load chat from localStorage on finding change
  useEffect(() => {
    setChatMessages(readChatCache(selectedFinding || undefined));
  }, [selectedFinding]);

  useEffect(() => {
    chatBottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [chatMessages, chatStreamText]);

  // ── Generic streaming trigger with cache
  async function triggerStream(
    stream: ReturnType<typeof useStream>,
    body: object,
    cacheAction: string,
    cacheId: string | number,
  ) {
    const cached = readCache(cacheAction, cacheId);
    if (cached) {
      stream.reset();
      // Animate cached content
      const words = cached.content.split(" ");
      let t = "";
      for (const w of words) {
        t += (t ? " " : "") + w;
        if (t.length > 20) {
          stream.reset();
          // Just set directly for cache hits
          break;
        }
      }
      // For cache: directly hydrate text via a mini stream simulation
      setCacheHits(p => ({ ...p, [cacheAction + ":" + cacheId]: cached.content }));
      return;
    }
    const result = await stream.run({ ...body, provider: selectedProvider || undefined });
    if (result.text) {
      writeCache(cacheAction, cacheId, {
        content: result.text,
        timestamp: new Date().toISOString(),
        model: result.model,
        usage: result.usage,
      });
      if (result.usage) addTokens(result.usage.totalTokens);
    }
  }

  function getCachedContent(action: string, id: string | number): { content: string; entry: CacheEntry } | null {
    const key = action + ":" + id;
    if (cacheHits[key]) return { content: cacheHits[key], entry: readCache(action, id)! };
    const entry = readCache(action, id);
    if (entry) return { content: entry.content, entry };
    return null;
  }

  // ── Chat send
  async function sendChat() {
    if (!chatInput.trim() || chatStreaming) return;
    const userMsg: ChatMessage = { role: "user", content: chatInput.trim(), timestamp: new Date().toISOString() };
    const newHistory = [...chatMessages, userMsg];
    setChatMessages(newHistory);
    setChatInput("");
    setChatStreamText("");
    setChatStreaming(true);

    const token = sessionStorage.getItem("ctem_token") ?? "";
    const contextMessages = newHistory.map(m => ({ role: m.role, content: m.content }));
    // Prepend finding context if selected
    const body: any = { action: "chat", messages: contextMessages, provider: selectedProvider || undefined };
    if (selectedFinding) body.findingId = parseInt(selectedFinding);

    let accumulated = "";
    let finalUsage: { totalTokens: number } | undefined;

    try {
      const resp = await fetch(`${BASE}/api/ai/stream`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
        body: JSON.stringify(body),
      });
      if (!resp.body) throw new Error("No stream");
      const reader = resp.body.getReader();
      const decoder = new TextDecoder();
      let buf = "";
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        const lines = buf.split("\n");
        buf = lines.pop() ?? "";
        for (const line of lines) {
          if (!line.startsWith("data: ")) continue;
          try {
            const d = JSON.parse(line.slice(6));
            if (d.text) { accumulated += d.text; setChatStreamText(accumulated); }
            if (d.usage) finalUsage = { totalTokens: d.usage.totalTokens ?? 0 };
          } catch { /* ignore */ }
        }
      }
    } catch { accumulated = accumulated || "Error generating response."; }

    const assistantMsg: ChatMessage = {
      role: "assistant", content: accumulated,
      timestamp: new Date().toISOString(),
      usage: finalUsage,
    };
    const finalHistory = [...newHistory, assistantMsg];
    setChatMessages(finalHistory);
    writeChatCache(selectedFinding || undefined, finalHistory);
    setChatStreamText("");
    setChatStreaming(false);
    if (finalUsage) addTokens(finalUsage.totalTokens);
  }

  function clearChat() {
    setChatMessages([]);
    writeChatCache(selectedFinding || undefined, []);
  }

  // ── Severity color helper
  const sevColor = (s: string) => ({ critical: "text-red-400", high: "text-orange-400", medium: "text-yellow-400", low: "text-blue-400" }[s] ?? "text-muted-foreground");

  // ── Cached content display helper
  function CachedOrStream({ stream: s, action, id }: { stream: ReturnType<typeof useStream>; action: string; id: string | number }) {
    const cached = getCachedContent(action, id);
    const displayText = s.text || cached?.content || "";
    const displayUsage = s.usage ?? cached?.entry.usage ?? null;
    const displayModel = s.provider ? `${s.provider}/${(providers.find(p => p.id === s.provider)?.model ?? "")}` : (cached?.entry.model ?? undefined);
    const generatedAt = !s.text ? cached?.entry.timestamp : undefined;
    if (!displayText && !s.streaming) return <p className="text-xs text-muted-foreground/60 italic">Select options above and click generate.</p>;
    return <AiOutput text={displayText} streaming={s.streaming} noKey={s.noKey} model={displayModel} usage={displayUsage} generatedAt={generatedAt} cacheHit={!!cached && !s.text} />;
  }

  // ── Inline stream + generate button helper
  function GenerateButton({ label, loadingLabel, onClick, disabled }: { label: string; loadingLabel: string; onClick: () => void; disabled?: boolean; }) {
    return (
      <Button size="sm" onClick={onClick} disabled={disabled} className="shrink-0 h-8 text-xs">
        {disabled ? <><Sparkles className="w-3 h-3 mr-1.5 animate-pulse" />{loadingLabel}</> : <>{label}</>}
      </Button>
    );
  }

  return (
    <div className="space-y-3">
      {/* Header */}
      <div className="flex items-start justify-between gap-3">
        <div>
          <h1 className="text-base font-semibold flex items-center gap-2">
            <Brain className="w-4 h-4 text-primary" />
            AI Security Copilot
          </h1>
          <p className="text-xs text-muted-foreground">Multi-provider AI: vulnerability analysis, remediation, compliance, and chat</p>
        </div>
        <div className="flex items-center gap-2 flex-shrink-0">
          {providersLoaded && (
            <ProviderBadge providers={providers} selected={selectedProvider} onSelect={setSelectedProvider} />
          )}
          <TokenCounter total={sessionTokens} requests={sessionRequests} />
        </div>
      </div>

      {/* No provider banner */}
      {providersLoaded && !providers.length && <NoKeyBanner />}

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList className="h-8 flex-wrap gap-0.5">
          <TabsTrigger value="explain"     className="text-[11px] h-7 gap-1"><Zap className="w-3 h-3" />Explain</TabsTrigger>
          <TabsTrigger value="remediation" className="text-[11px] h-7 gap-1"><Shield className="w-3 h-3" />Remediation</TabsTrigger>
          <TabsTrigger value="executive"   className="text-[11px] h-7 gap-1"><FileText className="w-3 h-3" />Executive</TabsTrigger>
          <TabsTrigger value="compliance"  className="text-[11px] h-7 gap-1"><ShieldCheck className="w-3 h-3" />Compliance</TabsTrigger>
          <TabsTrigger value="risk"        className="text-[11px] h-7 gap-1"><BarChart3 className="w-3 h-3" />Risk Score</TabsTrigger>
          <TabsTrigger value="scan"        className="text-[11px] h-7 gap-1"><Activity className="w-3 h-3" />Scan Triage</TabsTrigger>
          <TabsTrigger value="chat"        className="text-[11px] h-7 gap-1"><MessageSquare className="w-3 h-3" />Chat</TabsTrigger>
        </TabsList>

        {/* ── Tab: Explain Finding ─────────────────────────────────────────── */}
        <TabsContent value="explain" className="mt-3">
          <div className="bg-card border border-border rounded-xl p-4 space-y-3">
            <p className="text-xs text-muted-foreground">Get a detailed technical analysis of a vulnerability finding including CVE context, exploitability, and business impact.</p>
            <div className="flex gap-2">
              <Select value={selectedFinding} onValueChange={v => { setSelectedFinding(v); explainStream.reset(); }}>
                <SelectTrigger className="flex-1 h-8 text-xs">
                  <SelectValue placeholder="Select a finding to analyse…" />
                </SelectTrigger>
                <SelectContent className="max-h-72">
                  {findingList.map((f: any) => (
                    <SelectItem key={f.id} value={String(f.id)}>
                      <span className={cn("text-[10px] font-mono mr-1.5", sevColor(f.severity))}>[{(f.severity ?? "").toUpperCase()}]</span>
                      {f.title?.slice(0, 60)}
                      {f.cve && <span className="text-muted-foreground/60 ml-1">{f.cve}</span>}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <GenerateButton
                label="Explain"
                loadingLabel="Analysing…"
                disabled={!selectedFinding || explainStream.streaming}
                onClick={() => {
                  const cached = getCachedContent("explain", selectedFinding);
                  if (!cached) {
                    explainStream.run({ action: "explain-finding", findingId: parseInt(selectedFinding), provider: selectedProvider || undefined })
                      .then(r => { if (r.text) { writeCache("explain", selectedFinding, { content: r.text, timestamp: new Date().toISOString(), model: r.model, usage: r.usage }); if (r.usage) addTokens(r.usage.totalTokens); } });
                  }
                }}
              />
              {(explainStream.text || getCachedContent("explain", selectedFinding)) && (
                <Button size="sm" variant="ghost" className="h-8 w-8 p-0 text-muted-foreground" title="Clear cache"
                  onClick={() => { explainStream.reset(); setCacheHits(p => { const n = {...p}; delete n["explain:" + selectedFinding]; return n; }); try { localStorage.removeItem(cacheKey("explain", selectedFinding)); } catch {} }}>
                  <RotateCcw className="w-3.5 h-3.5" />
                </Button>
              )}
            </div>
            {selectedFinding && (() => { const f = findingList.find((x: any) => String(x.id) === selectedFinding); return f ? (
              <div className="flex flex-wrap items-center gap-1.5 text-[10px] bg-muted/20 rounded-lg px-2.5 py-1.5">
                {f.isKev && <Badge variant="outline" className="text-[9px] border-red-500/40 text-red-400 h-4 px-1">KEV</Badge>}
                <span className={cn("font-mono font-bold", sevColor(f.severity))}>{(f.severity ?? "").toUpperCase()}</span>
                <span className="text-muted-foreground truncate">{f.title}</span>
                {f.cve && <span className="text-blue-400/80 font-mono ml-auto shrink-0">{f.cve}</span>}
              </div>
            ) : null; })()}
            <div className="bg-muted/20 border border-border/40 rounded-xl p-4 min-h-36">
              <CachedOrStream stream={explainStream} action="explain" id={selectedFinding} />
            </div>
          </div>
        </TabsContent>

        {/* ── Tab: Remediation ─────────────────────────────────────────────── */}
        <TabsContent value="remediation" className="mt-3">
          <div className="bg-card border border-border rounded-xl p-4 space-y-3">
            <p className="text-xs text-muted-foreground">Step-by-step remediation plan with priority SLA, effort estimate, and reference links.</p>
            <div className="flex gap-2">
              <Select value={selectedFinding} onValueChange={v => { setSelectedFinding(v); remediationStream.reset(); }}>
                <SelectTrigger className="flex-1 h-8 text-xs">
                  <SelectValue placeholder="Select a finding…" />
                </SelectTrigger>
                <SelectContent className="max-h-72">
                  {findingList.map((f: any) => (
                    <SelectItem key={f.id} value={String(f.id)}>
                      <span className={cn("text-[10px] font-mono mr-1.5", sevColor(f.severity))}>[{(f.severity ?? "").toUpperCase()}]</span>
                      {f.title?.slice(0, 60)}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <GenerateButton
                label="Generate Plan"
                loadingLabel="Generating…"
                disabled={!selectedFinding || remediationStream.streaming}
                onClick={() => {
                  const cached = getCachedContent("remediation", selectedFinding);
                  if (!cached) {
                    remediationStream.run({ action: "remediation", findingId: parseInt(selectedFinding), provider: selectedProvider || undefined })
                      .then(r => { if (r.text) { writeCache("remediation", selectedFinding, { content: r.text, timestamp: new Date().toISOString(), model: r.model, usage: r.usage }); if (r.usage) addTokens(r.usage.totalTokens); } });
                  }
                }}
              />
              {(remediationStream.text || getCachedContent("remediation", selectedFinding)) && (
                <Button size="sm" variant="ghost" className="h-8 w-8 p-0 text-muted-foreground"
                  onClick={() => { remediationStream.reset(); try { localStorage.removeItem(cacheKey("remediation", selectedFinding)); } catch {} }}>
                  <RotateCcw className="w-3.5 h-3.5" />
                </Button>
              )}
            </div>
            <div className="bg-muted/20 border border-border/40 rounded-xl p-4 min-h-36">
              <CachedOrStream stream={remediationStream} action="remediation" id={selectedFinding} />
            </div>
          </div>
        </TabsContent>

        {/* ── Tab: Executive Summary ────────────────────────────────────────── */}
        <TabsContent value="executive" className="mt-3">
          <div className="bg-card border border-border rounded-xl p-4 space-y-3">
            <div className="flex items-start justify-between gap-2">
              <p className="text-xs text-muted-foreground">CISO-level executive briefing auto-generated from all your findings. No selection needed — reads your entire tenant's data.</p>
              <div className="flex gap-1.5 shrink-0">
                {(execStream.text || getCachedContent("executive", "global")) && (
                  <Button size="sm" variant="ghost" className="h-8 w-8 p-0 text-muted-foreground"
                    onClick={() => { execStream.reset(); try { localStorage.removeItem(cacheKey("executive", "global")); } catch {} }}>
                    <RotateCcw className="w-3.5 h-3.5" />
                  </Button>
                )}
                <GenerateButton
                  label="Generate"
                  loadingLabel="Generating…"
                  disabled={execStream.streaming}
                  onClick={() => {
                    const cached = getCachedContent("executive", "global");
                    if (!cached) {
                      execStream.run({ action: "executive-summary", provider: selectedProvider || undefined })
                        .then(r => { if (r.text) { writeCache("executive", "global", { content: r.text, timestamp: new Date().toISOString(), model: r.model, usage: r.usage }); if (r.usage) addTokens(r.usage.totalTokens); } });
                    }
                  }}
                />
              </div>
            </div>
            <div className="bg-muted/20 border border-border/40 rounded-xl p-4 min-h-40">
              <CachedOrStream stream={execStream} action="executive" id="global" />
            </div>
          </div>
        </TabsContent>

        {/* ── Tab: Compliance Guidance ──────────────────────────────────────── */}
        <TabsContent value="compliance" className="mt-3">
          <div className="bg-card border border-border rounded-xl p-4 space-y-3">
            <p className="text-xs text-muted-foreground">Implementation steps, evidence requirements, and pitfalls for any compliance control.</p>
            <div className="flex gap-2">
              <div className="relative flex-1">
                <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground pointer-events-none" />
                <Input
                  placeholder="Search controls…"
                  value={controlSearch}
                  onChange={e => setControlSearch(e.target.value)}
                  className="pl-8 h-8 text-xs"
                />
              </div>
              <Select value={selectedControl} onValueChange={v => { setSelectedControl(v); complianceStream.reset(); }}>
                <SelectTrigger className="flex-1 h-8 text-xs">
                  <SelectValue placeholder="Select control…" />
                </SelectTrigger>
                <SelectContent className="max-h-72">
                  {Object.entries(groupedControls).map(([fw, ctrls]) => (
                    <SelectGroup key={fw}>
                      <SelectLabel className="text-[10px]">{fw}</SelectLabel>
                      {(ctrls as any[]).map((c: any) => (
                        <SelectItem key={c.id} value={String(c.id)}>
                          <span className="font-mono text-[10px] text-muted-foreground mr-1">{c.controlId}</span>
                          {c.title?.slice(0, 50)}
                        </SelectItem>
                      ))}
                    </SelectGroup>
                  ))}
                </SelectContent>
              </Select>
              <GenerateButton
                label="Get Guidance"
                loadingLabel="Analysing…"
                disabled={!selectedControl || complianceStream.streaming}
                onClick={() => {
                  const cached = getCachedContent("compliance", selectedControl);
                  if (!cached) {
                    complianceStream.run({ action: "compliance-guidance", controlId: parseInt(selectedControl), provider: selectedProvider || undefined })
                      .then(r => { if (r.text) { writeCache("compliance", selectedControl, { content: r.text, timestamp: new Date().toISOString(), model: r.model, usage: r.usage }); if (r.usage) addTokens(r.usage.totalTokens); } });
                  }
                }}
              />
            </div>
            <div className="bg-muted/20 border border-border/40 rounded-xl p-4 min-h-36">
              <CachedOrStream stream={complianceStream} action="compliance" id={selectedControl} />
            </div>
          </div>
        </TabsContent>

        {/* ── Tab: Risk Score Explanation ───────────────────────────────────── */}
        <TabsContent value="risk" className="mt-3">
          <div className="bg-card border border-border rounded-xl p-4 space-y-3">
            <p className="text-xs text-muted-foreground">AI explanation of why an asset received its risk score — CVSS components, EPSS, KEV bonuses, and business impact.</p>
            <div className="flex gap-2">
              <Select value={selectedAsset} onValueChange={v => { setSelectedAsset(v); riskStream.reset(); }}>
                <SelectTrigger className="flex-1 h-8 text-xs">
                  <SelectValue placeholder="Select an asset…" />
                </SelectTrigger>
                <SelectContent className="max-h-72">
                  {findingList
                    .reduce((acc: any[], f: any) => { if (!acc.find((x: any) => x.assetId === f.assetId)) acc.push(f); return acc; }, [])
                    .map((f: any) => (
                      <SelectItem key={f.assetId} value={String(f.assetId)}>
                        Asset #{f.assetId}{f.assetName ? ` — ${f.assetName}` : ""}
                      </SelectItem>
                    ))}
                </SelectContent>
              </Select>
              <GenerateButton
                label="Explain Risk"
                loadingLabel="Analysing…"
                disabled={!selectedAsset || riskStream.streaming}
                onClick={() => {
                  const cached = getCachedContent("risk", selectedAsset);
                  if (!cached) {
                    riskStream.run({ action: "explain-risk-score", assetId: parseInt(selectedAsset), provider: selectedProvider || undefined })
                      .then(r => { if (r.text) { writeCache("risk", selectedAsset, { content: r.text, timestamp: new Date().toISOString(), model: r.model, usage: r.usage }); if (r.usage) addTokens(r.usage.totalTokens); } });
                  }
                }}
              />
            </div>
            <div className="bg-muted/20 border border-border/40 rounded-xl p-4 min-h-36">
              <CachedOrStream stream={riskStream} action="risk" id={selectedAsset} />
            </div>
          </div>
        </TabsContent>

        {/* ── Tab: Scan Triage ──────────────────────────────────────────────── */}
        <TabsContent value="scan" className="mt-3">
          <div className="bg-card border border-border rounded-xl p-4 space-y-3">
            <p className="text-xs text-muted-foreground">AI-powered triage of a completed scan — prioritised findings, key risk areas, and recommended next steps.</p>
            <div className="flex gap-2">
              <Select value={selectedScan} onValueChange={v => { setSelectedScan(v); scanStream.reset(); }}>
                <SelectTrigger className="flex-1 h-8 text-xs">
                  <SelectValue placeholder="Select a completed scan…" />
                </SelectTrigger>
                <SelectContent className="max-h-72">
                  {scanList.map((s: any) => (
                    <SelectItem key={s.id} value={String(s.id)}>
                      Scan #{s.id} · {s.type} · {s.completedAt ? new Date(s.completedAt).toLocaleDateString() : "—"}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <GenerateButton
                label="Triage"
                loadingLabel="Analysing…"
                disabled={!selectedScan || scanStream.streaming}
                onClick={() => {
                  const cached = getCachedContent("scan", selectedScan);
                  if (!cached) {
                    scanStream.run({ action: "summarize-scan", scanId: parseInt(selectedScan), provider: selectedProvider || undefined })
                      .then(r => { if (r.text) { writeCache("scan", selectedScan, { content: r.text, timestamp: new Date().toISOString(), model: r.model, usage: r.usage }); if (r.usage) addTokens(r.usage.totalTokens); } });
                  }
                }}
              />
            </div>
            <div className="bg-muted/20 border border-border/40 rounded-xl p-4 min-h-36">
              <CachedOrStream stream={scanStream} action="scan" id={selectedScan} />
            </div>
          </div>
        </TabsContent>

        {/* ── Tab: Chat ─────────────────────────────────────────────────────── */}
        <TabsContent value="chat" className="mt-3">
          <div className="bg-card border border-border rounded-xl flex flex-col" style={{ height: "calc(100vh - 280px)", minHeight: 420 }}>
            {/* Chat header */}
            <div className="flex items-center justify-between px-4 py-2.5 border-b border-border flex-shrink-0">
              <div className="flex items-center gap-2">
                <Brain className="w-4 h-4 text-primary" />
                <p className="text-xs font-medium">Security Copilot Chat</p>
                {selectedFinding && (() => { const f = findingList.find((x: any) => String(x.id) === selectedFinding); return f ? <Badge variant="outline" className="text-[9px]">Context: {f.title?.slice(0, 30)}</Badge> : null; })()}
              </div>
              <div className="flex items-center gap-2">
                <Select value={selectedFinding || "__none__"} onValueChange={v => { setSelectedFinding(v === "__none__" ? "" : v); }}>
                  <SelectTrigger className="h-6 text-[10px] w-36 border-border/50">
                    <SelectValue placeholder="No finding context" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="__none__" className="text-xs text-muted-foreground">No context</SelectItem>
                    {findingList.slice(0, 20).map((f: any) => (
                      <SelectItem key={f.id} value={String(f.id)} className="text-xs">
                        <span className={cn("font-mono mr-1", sevColor(f.severity))}>[{(f.severity ?? "").slice(0, 4).toUpperCase()}]</span>
                        {f.title?.slice(0, 30)}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                {chatMessages.length > 0 && (
                  <Button size="sm" variant="ghost" className="h-6 w-6 p-0 text-muted-foreground" onClick={clearChat} title="Clear conversation">
                    <Trash2 className="w-3 h-3" />
                  </Button>
                )}
              </div>
            </div>

            {/* Messages */}
            <div className="flex-1 overflow-y-auto p-4 space-y-3">
              {chatMessages.length === 0 && !chatStreaming && (
                <div className="flex flex-col items-center justify-center h-full text-center gap-3 text-muted-foreground/50">
                  <MessageSquare className="w-8 h-8" />
                  <p className="text-xs">Ask me anything about your vulnerabilities, risk scores, compliance controls, or security posture.</p>
                  <div className="flex flex-wrap gap-1.5 justify-center mt-1">
                    {["Explain critical findings", "What should I fix first?", "How do I improve my risk score?"].map(s => (
                      <button key={s} onClick={() => setChatInput(s)} className="text-[10px] border border-border/50 rounded-full px-2.5 py-0.5 hover:bg-accent transition-colors">{s}</button>
                    ))}
                  </div>
                </div>
              )}
              {chatMessages.map((m, i) => (
                <div key={i} className={cn("flex gap-2", m.role === "user" ? "justify-end" : "justify-start")}>
                  {m.role === "assistant" && <div className="w-6 h-6 rounded-full bg-primary/15 flex items-center justify-center shrink-0 mt-0.5"><Bot className="w-3.5 h-3.5 text-primary" /></div>}
                  <div className={cn("max-w-[80%] rounded-xl px-3 py-2 text-xs", m.role === "user" ? "bg-primary text-primary-foreground" : "bg-muted/40 border border-border/40")}>
                    {m.role === "user" ? (
                      <p className="leading-relaxed">{m.content}</p>
                    ) : (
                      <AiMarkdown content={m.content} />
                    )}
                    {m.usage && <p className="text-[9px] opacity-40 mt-1">{m.usage.totalTokens.toLocaleString()} tokens</p>}
                  </div>
                  {m.role === "user" && <div className="w-6 h-6 rounded-full bg-muted/40 flex items-center justify-center shrink-0 mt-0.5"><User className="w-3.5 h-3.5 text-muted-foreground" /></div>}
                </div>
              ))}
              {chatStreaming && (
                <div className="flex gap-2 justify-start">
                  <div className="w-6 h-6 rounded-full bg-primary/15 flex items-center justify-center shrink-0 mt-0.5"><Bot className="w-3.5 h-3.5 text-primary" /></div>
                  <div className="max-w-[80%] rounded-xl px-3 py-2 bg-muted/40 border border-border/40 text-xs">
                    {chatStreamText ? <AiMarkdown content={chatStreamText} /> : (
                      <span className="flex items-center gap-1.5 text-muted-foreground"><Sparkles className="w-3 h-3 animate-pulse" /> Thinking…</span>
                    )}
                    <span className="inline-block w-1 h-3.5 bg-primary/70 animate-pulse ml-0.5 rounded-sm" />
                  </div>
                </div>
              )}
              <div ref={chatBottomRef} />
            </div>

            {/* Input */}
            <div className="p-3 border-t border-border flex-shrink-0">
              <div className="flex gap-2">
                <Textarea
                  value={chatInput}
                  onChange={e => setChatInput(e.target.value)}
                  onKeyDown={e => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); sendChat(); } }}
                  placeholder="Ask about findings, risks, compliance, remediation… (Enter to send)"
                  className="text-xs resize-none min-h-[36px] max-h-24"
                  rows={1}
                  disabled={chatStreaming}
                />
                <Button size="sm" onClick={sendChat} disabled={!chatInput.trim() || chatStreaming} className="h-9 w-9 p-0 shrink-0">
                  {chatStreaming ? <Sparkles className="w-3.5 h-3.5 animate-pulse" /> : <Send className="w-3.5 h-3.5" />}
                </Button>
              </div>
            </div>
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
}
