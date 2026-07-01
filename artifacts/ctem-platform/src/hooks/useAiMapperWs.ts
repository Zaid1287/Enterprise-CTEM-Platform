import { useEffect, useRef, useState } from "react";
import { getToken } from "@/lib/auth";

interface UseAiMapperWsOptions {
  url: string | null;
  onMessage: (data: unknown) => void;
  enabled?: boolean;
  /** Optional SSE fallback URL. EventSource is started when WS fails and sseUrl is provided. */
  sseUrl?: string | null;
}

function buildAbsWsUrl(path: string): string {
  const token = getToken();
  const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
  const abs = path.startsWith("http") ? path : `${proto}//${window.location.host}${path}`;
  const wsAbs = abs.startsWith("http") ? abs.replace(/^http/, "ws") : abs;
  return `${wsAbs}?token=${encodeURIComponent(token ?? "")}`;
}

function buildAbsSseUrl(path: string): string {
  const token = getToken();
  const abs = path.startsWith("http") ? path : `${window.location.origin}${path}`;
  return `${abs}${abs.includes("?") ? "&" : "?"}token=${encodeURIComponent(token ?? "")}`;
}

export function useAiMapperWs({ url, onMessage, enabled = true, sseUrl }: UseAiMapperWsOptions) {
  const [connected, setConnected] = useState(false);
  const onMessageRef = useRef(onMessage);
  onMessageRef.current = onMessage;

  useEffect(() => {
    if (!enabled || !url) return;

    let cancelled = false;
    let ws: WebSocket | null = null;
    let sse: EventSource | null = null;

    function startSse() {
      if (cancelled || !sseUrl) return;
      sse = new EventSource(buildAbsSseUrl(sseUrl));
      sse.onmessage = (e) => {
        try { onMessageRef.current(JSON.parse(e.data)); } catch { /* ignore */ }
      };
      sse.onerror = () => { sse?.close(); sse = null; };
    }

    try {
      ws = new WebSocket(buildAbsWsUrl(url));

      ws.onopen = () => { if (!cancelled) setConnected(true); };

      ws.onmessage = (e) => {
        try { onMessageRef.current(JSON.parse(e.data)); } catch { /* ignore */ }
      };

      ws.onerror = () => {
        if (!cancelled) { setConnected(false); startSse(); }
      };

      ws.onclose = () => {
        if (!cancelled) setConnected(false);
      };
    } catch {
      startSse();
    }

    return () => {
      cancelled = true;
      setConnected(false);
      ws?.close();
      sse?.close();
    };
  }, [url, sseUrl, enabled]);

  return { connected };
}
