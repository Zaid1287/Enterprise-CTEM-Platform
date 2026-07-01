import { useEffect, useRef, useState } from "react";
import { getToken } from "@/lib/auth";

interface UseAiMapperWsOptions {
  url: string | null;
  onMessage: (data: unknown) => void;
  enabled?: boolean;
}

export function useAiMapperWs({ url, onMessage, enabled = true }: UseAiMapperWsOptions) {
  const [connected, setConnected] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);
  const onMessageRef = useRef(onMessage);
  onMessageRef.current = onMessage;

  useEffect(() => {
    if (!enabled || !url) return;

    const token = getToken();
    const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
    const absoluteUrl = url.startsWith("http") ? url : `${proto}//${window.location.host}${url}`;
    const wsUrl = absoluteUrl.replace(/^http/, "ws") + `?token=${encodeURIComponent(token ?? "")}`;

    let ws: WebSocket;
    try {
      ws = new WebSocket(wsUrl);
      wsRef.current = ws;

      ws.onopen = () => setConnected(true);
      ws.onmessage = (e) => {
        try { onMessageRef.current(JSON.parse(e.data)); } catch { /* ignore */ }
      };
      ws.onerror = () => setConnected(false);
      ws.onclose = () => setConnected(false);
    } catch {
      setConnected(false);
    }

    return () => {
      wsRef.current?.close();
      wsRef.current = null;
      setConnected(false);
    };
  }, [url, enabled]);

  return {
    connected,
    close: () => { wsRef.current?.close(); },
  };
}
