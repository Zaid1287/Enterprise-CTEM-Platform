import type { Response } from "express";

// ── Alert / general SSE connections (tenant-scoped) ──────────────────────────
const connections = new Map<number, Set<Response>>();

export function addSseClient(tenantId: number, res: Response): void {
  if (!connections.has(tenantId)) connections.set(tenantId, new Set());
  connections.get(tenantId)!.add(res);
}

export function removeSseClient(tenantId: number, res: Response): void {
  const set = connections.get(tenantId);
  if (!set) return;
  set.delete(res);
  if (set.size === 0) connections.delete(tenantId);
}

export function pushSseEvent(tenantId: number, event: string, data: unknown): void {
  const clients = connections.get(tenantId);
  if (!clients || clients.size === 0) return;
  const msg = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  const dead: Response[] = [];
  for (const res of clients) {
    try { res.write(msg); } catch { dead.push(res); }
  }
  for (const r of dead) removeSseClient(tenantId, r);
}

// ── Waterfall / telemetry SSE connections (tenant-scoped) ────────────────────
// Each admin connects here to receive real-time request waterfall events.
const waterfallConnections = new Map<number, Set<Response>>();

export function addWaterfallSseClient(tenantId: number, res: Response): void {
  if (!waterfallConnections.has(tenantId)) waterfallConnections.set(tenantId, new Set());
  waterfallConnections.get(tenantId)!.add(res);
}

export function removeWaterfallSseClient(tenantId: number, res: Response): void {
  const set = waterfallConnections.get(tenantId);
  if (!set) return;
  set.delete(res);
  if (set.size === 0) waterfallConnections.delete(tenantId);
}

export function pushWaterfallEvent(tenantId: number, data: unknown): void {
  const clients = waterfallConnections.get(tenantId);
  if (!clients || clients.size === 0) return;
  const msg = `event: telemetry:request\ndata: ${JSON.stringify(data)}\n\n`;
  const dead: Response[] = [];
  for (const res of clients) {
    try { res.write(msg); } catch { dead.push(res); }
  }
  for (const r of dead) removeWaterfallSseClient(tenantId, r);
}

export function pushWaterfallDegradedEvent(tenantId: number, data: unknown): void {
  const clients = waterfallConnections.get(tenantId);
  if (!clients || clients.size === 0) return;
  const msg = `event: telemetry:degraded_mode\ndata: ${JSON.stringify(data)}\n\n`;
  const dead: Response[] = [];
  for (const res of clients) {
    try { res.write(msg); } catch { dead.push(res); }
  }
  for (const r of dead) removeWaterfallSseClient(tenantId, r);
}
