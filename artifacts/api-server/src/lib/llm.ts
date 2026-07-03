import { logger } from "./logger";
import { getUserApiKey } from "../routes/userAiSettings";
import { getPlatformSetting } from "../routes/platformSettings";

export type Provider = "openai" | "anthropic" | "gemini" | "openrouter" | "ollama";

export interface LLMMessage {
  role: "system" | "user" | "assistant";
  content: string;
}

export interface ProviderConfig {
  provider: Provider;
  apiKey: string;
  baseUrl?: string | null;
  model: string;
  source: "user" | "platform" | "env";
}

export interface LLMUsage {
  promptTokens: number;
  completionTokens: number;
  totalTokens: number;
}

export interface LLMResult {
  text: string | null;
  usage?: LLMUsage;
}

const DEFAULT_MODELS: Record<Provider, string> = {
  openai:     "gpt-4o-mini",
  anthropic:  "claude-3-haiku-20240307",
  gemini:     "gemini-2.0-flash",
  openrouter: "openai/gpt-4o-mini",
  ollama:     "llama3.2",
};

const PLATFORM_KEYS: Record<Provider, string> = {
  openai:     "openai_api_key",
  anthropic:  "anthropic_api_key",
  gemini:     "gemini_api_key",
  openrouter: "openrouter_api_key",
  ollama:     "ollama_base_url",
};

const ALL_PROVIDERS: Provider[] = ["openai", "anthropic", "gemini", "openrouter", "ollama"];

// ── Provider discovery ──────────────────────────────────────────────────────

/** Returns all configured providers for a user in priority order */
export async function getAvailableProviders(userId: number): Promise<ProviderConfig[]> {
  const result: ProviderConfig[] = [];

  for (const p of ALL_PROVIDERS) {
    // 1. User-saved key (highest priority)
    const userKey = await getUserApiKey(userId, p);
    if (p === "ollama") {
      const baseUrl = userKey?.baseUrl ?? await getPlatformSetting(PLATFORM_KEYS.ollama);
      if (baseUrl) {
        result.push({ provider: "ollama", apiKey: "", baseUrl, model: DEFAULT_MODELS.ollama, source: userKey ? "user" : "platform" });
      }
      continue;
    }
    if (userKey?.apiKey) {
      result.push({ provider: p, apiKey: userKey.apiKey, baseUrl: userKey.baseUrl, model: DEFAULT_MODELS[p], source: "user" });
      continue;
    }
    // 2. Platform settings
    const platformKey = await getPlatformSetting(PLATFORM_KEYS[p]);
    if (platformKey) {
      result.push({ provider: p, apiKey: platformKey, model: DEFAULT_MODELS[p], source: "platform" });
      continue;
    }
    // 3. Env var (only OpenAI)
    if (p === "openai" && process.env.OPENAI_API_KEY) {
      result.push({ provider: "openai", apiKey: process.env.OPENAI_API_KEY, model: DEFAULT_MODELS.openai, source: "env" });
    }
  }

  return result;
}

/** Resolve the best provider config for a request */
export async function resolveProviderConfig(
  userId: number,
  preferredProvider?: Provider | null,
): Promise<ProviderConfig | null> {
  const available = await getAvailableProviders(userId);
  if (!available.length) return null;
  if (preferredProvider) {
    const match = available.find(p => p.provider === preferredProvider);
    if (match) return match;
  }
  return available[0];
}

/** Synchronous check — env var only (for legacy routes) */
export function isLLMAvailable(): boolean {
  return !!process.env.OPENAI_API_KEY;
}

// ── Non-streaming completion ────────────────────────────────────────────────

export async function llmComplete(
  messages: LLMMessage[],
  options: { maxTokens?: number; model?: string } = {},
  config?: ProviderConfig | null,
): Promise<LLMResult> {
  if (!config) return { text: null };
  const { maxTokens = 1500 } = options;
  const model = options.model ?? config.model;
  try {
    switch (config.provider) {
      case "openai":
      case "openrouter": return await _openAICompat(messages, model, maxTokens, config);
      case "anthropic":  return await _anthropic(messages, model, maxTokens, config);
      case "gemini":     return await _gemini(messages, model, maxTokens, config);
      case "ollama":     return await _ollama(messages, model, maxTokens, config);
    }
  } catch (err) {
    logger.error({ err, provider: config.provider }, "llmComplete failed");
    return { text: null };
  }
}

// ── Streaming ───────────────────────────────────────────────────────────────

export async function llmStream(
  messages: LLMMessage[],
  options: { maxTokens?: number; model?: string },
  config: ProviderConfig,
  onChunk: (text: string) => void,
  onDone: (usage?: LLMUsage) => void,
): Promise<void> {
  const { maxTokens = 1500 } = options;
  const model = options.model ?? config.model;
  try {
    switch (config.provider) {
      case "openai":
      case "openrouter": await _streamOpenAICompat(messages, model, maxTokens, config, onChunk, onDone); break;
      case "anthropic":  await _streamAnthropic(messages, model, maxTokens, config, onChunk, onDone); break;
      case "gemini":     await _streamGemini(messages, model, maxTokens, config, onChunk, onDone); break;
      case "ollama":     await _streamOllama(messages, model, maxTokens, config, onChunk, onDone); break;
    }
  } catch (err) {
    logger.error({ err, provider: config.provider }, "llmStream failed");
    onDone();
  }
}

/** Stream template text word-by-word for consistent UX even in no-key mode */
export async function streamTemplate(
  text: string,
  onChunk: (text: string) => void,
  onDone: (usage?: LLMUsage) => void,
): Promise<void> {
  const words = text.split(" ");
  let batch = "";
  for (const word of words) {
    batch += (batch ? " " : "") + word;
    if (batch.length >= 18) {
      onChunk(batch);
      batch = "";
      await new Promise(r => setTimeout(r, 14));
    }
  }
  if (batch) onChunk(batch);
  onDone({ promptTokens: 0, completionTokens: 0, totalTokens: 0 });
}

// ── SSE line reader helper ──────────────────────────────────────────────────

async function* readSSELines(body: ReadableStream<Uint8Array>) {
  const reader = body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    const lines = buffer.split("\n");
    buffer = lines.pop() ?? "";
    for (const line of lines) yield line;
  }
  for (const line of buffer.split("\n")) if (line) yield line;
}

// ── OpenAI / OpenRouter ─────────────────────────────────────────────────────

function openAIHeaders(config: ProviderConfig) {
  return {
    "Content-Type": "application/json",
    "Authorization": `Bearer ${config.apiKey}`,
    ...(config.provider === "openrouter" ? {
      "HTTP-Referer": "https://sentinelware.io",
      "X-Title": "Sentinelware CTEM",
    } : {}),
  };
}

function openAIBase(config: ProviderConfig) {
  return config.baseUrl?.replace(/\/$/, "")
    ?? (config.provider === "openrouter" ? "https://openrouter.ai/api/v1" : "https://api.openai.com/v1");
}

async function _openAICompat(messages: LLMMessage[], model: string, maxTokens: number, config: ProviderConfig): Promise<LLMResult> {
  const res = await fetch(`${openAIBase(config)}/chat/completions`, {
    method: "POST", headers: openAIHeaders(config),
    body: JSON.stringify({ model, messages, max_tokens: maxTokens }),
  });
  if (!res.ok) { logger.error({ status: res.status, provider: config.provider }, "OpenAI error"); return { text: null }; }
  const d = await res.json() as any;
  return {
    text: d.choices?.[0]?.message?.content ?? null,
    usage: d.usage ? { promptTokens: d.usage.prompt_tokens, completionTokens: d.usage.completion_tokens, totalTokens: d.usage.total_tokens } : undefined,
  };
}

async function _streamOpenAICompat(messages: LLMMessage[], model: string, maxTokens: number, config: ProviderConfig, onChunk: (t: string) => void, onDone: (u?: LLMUsage) => void) {
  const res = await fetch(`${openAIBase(config)}/chat/completions`, {
    method: "POST", headers: openAIHeaders(config),
    body: JSON.stringify({ model, messages, max_tokens: maxTokens, stream: true, stream_options: { include_usage: true } }),
  });
  if (!res.ok) { logger.error({ status: res.status, provider: config.provider }, "OpenAI stream error"); onDone(); return; }

  let usage: LLMUsage | undefined;
  for await (const line of readSSELines(res.body!)) {
    if (!line.startsWith("data: ")) continue;
    const raw = line.slice(6).trim();
    if (raw === "[DONE]") continue;
    try {
      const d = JSON.parse(raw) as any;
      const delta = d.choices?.[0]?.delta?.content;
      if (delta) onChunk(delta);
      if (d.usage) usage = { promptTokens: d.usage.prompt_tokens, completionTokens: d.usage.completion_tokens, totalTokens: d.usage.total_tokens };
    } catch { /* ignore */ }
  }
  onDone(usage);
}

// ── Anthropic ───────────────────────────────────────────────────────────────

function toAnthropicMsgs(messages: LLMMessage[]) {
  const system = messages.filter(m => m.role === "system").map(m => m.content).join("\n");
  const msgs = messages.filter(m => m.role !== "system").map(m => ({ role: m.role as "user" | "assistant", content: m.content }));
  return { system, msgs };
}

async function _anthropic(messages: LLMMessage[], model: string, maxTokens: number, config: ProviderConfig): Promise<LLMResult> {
  const { system, msgs } = toAnthropicMsgs(messages);
  const res = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: { "Content-Type": "application/json", "x-api-key": config.apiKey, "anthropic-version": "2023-06-01" },
    body: JSON.stringify({ model, max_tokens: maxTokens, ...(system ? { system } : {}), messages: msgs }),
  });
  if (!res.ok) { logger.error({ status: res.status }, "Anthropic error"); return { text: null }; }
  const d = await res.json() as any;
  return {
    text: d.content?.[0]?.text ?? null,
    usage: d.usage ? { promptTokens: d.usage.input_tokens, completionTokens: d.usage.output_tokens, totalTokens: (d.usage.input_tokens ?? 0) + (d.usage.output_tokens ?? 0) } : undefined,
  };
}

async function _streamAnthropic(messages: LLMMessage[], model: string, maxTokens: number, config: ProviderConfig, onChunk: (t: string) => void, onDone: (u?: LLMUsage) => void) {
  const { system, msgs } = toAnthropicMsgs(messages);
  const res = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: { "Content-Type": "application/json", "x-api-key": config.apiKey, "anthropic-version": "2023-06-01" },
    body: JSON.stringify({ model, max_tokens: maxTokens, ...(system ? { system } : {}), messages: msgs, stream: true }),
  });
  if (!res.ok) { logger.error({ status: res.status }, "Anthropic stream error"); onDone(); return; }

  let inputTokens = 0, outputTokens = 0;
  for await (const line of readSSELines(res.body!)) {
    if (!line.startsWith("data: ")) continue;
    try {
      const d = JSON.parse(line.slice(6)) as any;
      if (d.type === "content_block_delta" && d.delta?.type === "text_delta") onChunk(d.delta.text);
      if (d.type === "message_start" && d.message?.usage) inputTokens = d.message.usage.input_tokens ?? 0;
      if (d.type === "message_delta" && d.usage) outputTokens = d.usage.output_tokens ?? 0;
    } catch { /* ignore */ }
  }
  onDone({ promptTokens: inputTokens, completionTokens: outputTokens, totalTokens: inputTokens + outputTokens });
}

// ── Gemini ──────────────────────────────────────────────────────────────────

function toGeminiContents(messages: LLMMessage[]) {
  const roleMap: Record<string, string> = { user: "user", assistant: "model" };
  return messages.filter(m => m.role !== "system").map(m => ({ role: roleMap[m.role] ?? "user", parts: [{ text: m.content }] }));
}

function geminiBody(messages: LLMMessage[], maxTokens: number) {
  const sys = messages.find(m => m.role === "system");
  const body: any = { contents: toGeminiContents(messages), generationConfig: { maxOutputTokens: maxTokens } };
  if (sys) body.systemInstruction = { parts: [{ text: sys.content }] };
  return body;
}

async function _gemini(messages: LLMMessage[], model: string, maxTokens: number, config: ProviderConfig): Promise<LLMResult> {
  const res = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${config.apiKey}`,
    { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(geminiBody(messages, maxTokens)) });
  if (!res.ok) { logger.error({ status: res.status }, "Gemini error"); return { text: null }; }
  const d = await res.json() as any;
  const meta = d.usageMetadata;
  return {
    text: d.candidates?.[0]?.content?.parts?.[0]?.text ?? null,
    usage: meta ? { promptTokens: meta.promptTokenCount ?? 0, completionTokens: meta.candidatesTokenCount ?? 0, totalTokens: meta.totalTokenCount ?? 0 } : undefined,
  };
}

async function _streamGemini(messages: LLMMessage[], model: string, maxTokens: number, config: ProviderConfig, onChunk: (t: string) => void, onDone: (u?: LLMUsage) => void) {
  const res = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${model}:streamGenerateContent?alt=sse&key=${config.apiKey}`,
    { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(geminiBody(messages, maxTokens)) });
  if (!res.ok) { logger.error({ status: res.status }, "Gemini stream error"); onDone(); return; }

  let usage: LLMUsage | undefined;
  for await (const line of readSSELines(res.body!)) {
    if (!line.startsWith("data: ")) continue;
    try {
      const d = JSON.parse(line.slice(6)) as any;
      const text = d.candidates?.[0]?.content?.parts?.[0]?.text;
      if (text) onChunk(text);
      const meta = d.usageMetadata;
      if (meta) usage = { promptTokens: meta.promptTokenCount ?? 0, completionTokens: meta.candidatesTokenCount ?? 0, totalTokens: meta.totalTokenCount ?? 0 };
    } catch { /* ignore */ }
  }
  onDone(usage);
}

// ── Ollama ──────────────────────────────────────────────────────────────────

function ollamaBase(config: ProviderConfig) {
  return (config.baseUrl ?? "http://localhost:11434").replace(/\/$/, "");
}

async function _ollama(messages: LLMMessage[], model: string, maxTokens: number, config: ProviderConfig): Promise<LLMResult> {
  const res = await fetch(`${ollamaBase(config)}/api/chat`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ model, messages, stream: false, options: { num_predict: maxTokens } }),
  });
  if (!res.ok) { logger.error({ status: res.status }, "Ollama error"); return { text: null }; }
  const d = await res.json() as any;
  return {
    text: d.message?.content ?? null,
    usage: { promptTokens: d.prompt_eval_count ?? 0, completionTokens: d.eval_count ?? 0, totalTokens: (d.prompt_eval_count ?? 0) + (d.eval_count ?? 0) },
  };
}

async function _streamOllama(messages: LLMMessage[], model: string, maxTokens: number, config: ProviderConfig, onChunk: (t: string) => void, onDone: (u?: LLMUsage) => void) {
  const res = await fetch(`${ollamaBase(config)}/api/chat`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ model, messages, stream: true, options: { num_predict: maxTokens } }),
  });
  if (!res.ok) { logger.error({ status: res.status }, "Ollama stream error"); onDone(); return; }

  const reader = res.body!.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  let usage: LLMUsage | undefined;

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    const lines = buffer.split("\n");
    buffer = lines.pop() ?? "";
    for (const line of lines) {
      if (!line.trim()) continue;
      try {
        const d = JSON.parse(line) as any;
        if (d.message?.content) onChunk(d.message.content);
        if (d.done) usage = { promptTokens: d.prompt_eval_count ?? 0, completionTokens: d.eval_count ?? 0, totalTokens: (d.prompt_eval_count ?? 0) + (d.eval_count ?? 0) };
      } catch { /* ignore */ }
    }
  }
  onDone(usage);
}
