import type { Response } from "express";

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
