import { useEffect, useRef } from "react";
import { getToken } from "@/lib/auth";

interface UseAiMapperStreamOptions {
  url: string | null;
  onMessage: (data: unknown) => void;
  enabled?: boolean;
}

export function useAiMapperStream({ url, onMessage, enabled = true }: UseAiMapperStreamOptions) {
  const onMessageRef = useRef(onMessage);
  onMessageRef.current = onMessage;
  const cleanupRef = useRef<(() => void) | null>(null);

  useEffect(() => {
    if (!enabled || !url) return;

    const token = getToken();

    let cancelled = false;
    let wsConnected = false;

    const wsUrl = url.replace(/^http/, "ws") + `?token=${encodeURIComponent(token ?? "")}`;
    let ws: WebSocket | null = null;
    let sseSource: EventSource | null = null;

    function startSse() {
      if (cancelled) return;
      const sseUrl = url!.replace(/\/ws$/, "/stream") + `?token=${encodeURIComponent(token ?? "")}`;
      sseSource = new EventSource(sseUrl);
      sseSource.onmessage = (e) => {
        try { onMessageRef.current(JSON.parse(e.data)); } catch { /* ignore */ }
      };
      sseSource.onerror = () => {
        sseSource?.close();
        sseSource = null;
      };
    }

    try {
      ws = new WebSocket(wsUrl);

      const connTimeout = setTimeout(() => {
        if (!wsConnected && !cancelled) {
          ws?.close();
          startSse();
        }
      }, 3000);

      ws.onopen = () => {
        wsConnected = true;
        clearTimeout(connTimeout);
      };

      ws.onmessage = (e) => {
        try { onMessageRef.current(JSON.parse(e.data)); } catch { /* ignore */ }
      };

      ws.onerror = () => {
        clearTimeout(connTimeout);
        if (!cancelled) startSse();
      };

      ws.onclose = () => {
        clearTimeout(connTimeout);
      };
    } catch {
      startSse();
    }

    cleanupRef.current = () => {
      cancelled = true;
      ws?.close();
      sseSource?.close();
    };

    return () => {
      cleanupRef.current?.();
      cleanupRef.current = null;
    };
  }, [url, enabled]);
}
