export interface ShodanPreset {
  id: string;
  label: string;
  protocol: string;
  query: string;
}

export const SHODAN_PRESETS: ShodanPreset[] = [
  { id: "mcp-product",        label: "MCP Server (product)",        protocol: "mcp",        query: 'product:"mcp-server"' },
  { id: "mcp-sse-html",       label: "MCP SSE endpoint",            protocol: "mcp",        query: 'http.html:"mcp/sse"' },
  { id: "mcp-sse-200",        label: "MCP SSE (200 OK)",            protocol: "mcp",        query: 'http.html:"/mcp/sse" http.status:200' },
  { id: "mcp-toolslist",      label: "MCP tools/list port 3000",    protocol: "mcp",        query: 'port:3000 http.html:"tools/list"' },

  { id: "ollama-product",     label: "Ollama (product)",            protocol: "ollama",     query: 'product:"Ollama"' },
  { id: "ollama-port",        label: "Ollama port 11434",           protocol: "ollama",     query: "port:11434" },
  { id: "ollama-html",        label: "Ollama HTML fingerprint",     protocol: "ollama",     query: 'http.html:"ollama" port:11434' },

  { id: "vllm-html",          label: "vLLM /v1/models",             protocol: "vllm",       query: 'http.html:"/v1/models" http.html:"vllm"' },
  { id: "openai-compat",      label: "OpenAI-compat /v1/chat",      protocol: "vllm",       query: 'http.html:"/v1/chat/completions"' },
  { id: "litellm-product",    label: "LiteLLM (product)",           protocol: "litellm",    query: 'product:"LiteLLM"' },
  { id: "localai-html",       label: "LocalAI HTML",                protocol: "localai",    query: 'http.html:"LocalAI"' },

  { id: "langserve-html",     label: "LangServe HTML",              protocol: "langserve",  query: 'http.html:"langserve"' },
  { id: "langserve-playground", label: "LangServe Playground",      protocol: "langserve",  query: 'http.html:"LangServe Playground"' },

  { id: "openclaw-port",      label: "OpenClaw port 18789",         protocol: "openclaw",   query: "port:18789" },
  { id: "clawdbot-html",      label: "Clawdbot HTML",               protocol: "openclaw",   query: 'http.html:"Clawdbot"' },
  { id: "openclaw-html",      label: "OpenClaw HTML",               protocol: "openclaw",   query: 'http.html:"OpenClaw"' },

  { id: "openwebui-title",    label: "Open WebUI title",            protocol: "openwebui",  query: 'http.title:"Open WebUI"' },
  { id: "librechat-title",    label: "LibreChat title",             protocol: "librechat",  query: 'http.title:"LibreChat"' },

  { id: "gradio-title",       label: "Gradio title",                protocol: "gradio",     query: 'http.title:"Gradio"' },
  { id: "gradio-favicon",     label: "Gradio favicon hash",         protocol: "gradio",     query: 'http.html:"gradio" http.favicon.hash:-1074136498' },
  { id: "gradio-app",         label: "Gradio app tag",              protocol: "gradio",     query: 'http.html:"<gradio-app"' },

  { id: "streamlit-title",    label: "Streamlit title",             protocol: "streamlit",  query: 'http.title:"Streamlit"' },
  { id: "streamlit-favicon",  label: "Streamlit favicon hash",      protocol: "streamlit",  query: "http.favicon.hash:1928819960" },

  { id: "comfyui-title",      label: "ComfyUI title",               protocol: "comfyui",    query: 'http.title:"ComfyUI"' },
  { id: "comfyui-port",       label: "ComfyUI port 8188",           protocol: "comfyui",    query: 'port:8188 http.html:"comfy"' },
  { id: "stablediff-title",   label: "Stable Diffusion title",      protocol: "stablediff", query: 'http.title:"Stable Diffusion"' },
  { id: "a1111-html",         label: "AUTOMATIC1111 HTML",          protocol: "stablediff", query: 'http.html:"AUTOMATIC1111"' },

  { id: "tgi-html",           label: "HuggingFace TGI HTML",        protocol: "tgi",        query: 'http.html:"text-generation-inference"' },

  { id: "generic-generate",   label: "Generic /api/generate",       protocol: "generic",    query: 'http.html:"/api/generate"' },
  { id: "generic-tags",       label: "Generic /api/tags",           protocol: "generic",    query: 'http.html:"/api/tags"' },
];

export const PROTOCOL_COLORS: Record<string, string> = {
  mcp:        "#3b82f6",
  ollama:     "#22c55e",
  vllm:       "#a855f7",
  langserve:  "#f97316",
  gradio:     "#ec4899",
  comfyui:    "#eab308",
  litellm:    "#a855f7",
  localai:    "#a855f7",
  openwebui:  "#06b6d4",
  librechat:  "#06b6d4",
  streamlit:  "#f43f5e",
  stablediff: "#8b5cf6",
  tgi:        "#f59e0b",
  openclaw:   "#ef4444",
  generic:    "#ef4444",
};
