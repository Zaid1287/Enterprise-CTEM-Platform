import { useEffect, useRef } from "react";
import { getToken } from "@/lib/auth";

interface UseAiMapperStreamOptions {
  url: string | null;
  onMessage: (data: unknown) => void;
  enabled?: boolean;
}

function buildWsUrl(url: string): string {
  const token = getToken();
  const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
  const abs = url.startsWith("http") ? url : `${proto}//${window.location.host}${url}`;
  return abs.replace(/^http/, "ws") + `?token=${encodeURIComponent(token ?? "")}`;
}

export function useAiMapperStream({ url, onMessage, enabled = true }: UseAiMapperStreamOptions) {
  const onMessageRef = useRef(onMessage);
  onMessageRef.current = onMessage;

  useEffect(() => {
    if (!enabled || !url) return;

    let cancelled = false;
    let ws: WebSocket | null = null;

    try {
      ws = new WebSocket(buildWsUrl(url));

      ws.onmessage = (e) => {
        try { onMessageRef.current(JSON.parse(e.data)); } catch { /* ignore */ }
      };
      ws.onerror = () => {
        ws?.close();
        ws = null;
      };
    } catch {
      /* no-op — polling fallback handles live updates */
    }

    return () => {
      cancelled = true;
      void cancelled;
      ws?.close();
      ws = null;
    };
  }, [url, enabled]);
}
