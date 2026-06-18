import { Router } from "express";
import { eq, and, desc } from "drizzle-orm";
import { db, sessionsTable } from "@workspace/db";
import { requireAuth, type AuthenticatedRequest } from "../lib/auth";

const router = Router();

// ── List active sessions ───────────────────────────────────────────────────────

router.get("/auth/sessions", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const userId = req.user!.userId;

  const sessions = await db
    .select()
    .from(sessionsTable)
    .where(and(eq(sessionsTable.userId, userId), eq(sessionsTable.isActive, true)))
    .orderBy(desc(sessionsTable.lastActiveAt));

  res.json(sessions.map(s => ({
    id: s.id,
    ipAddress: s.ipAddress,
    device: s.device,
    browser: s.browser,
    os: s.os,
    location: s.location,
    userAgent: s.userAgent,
    lastActiveAt: s.lastActiveAt.toISOString(),
    createdAt: s.createdAt.toISOString(),
    expiresAt: s.expiresAt.toISOString(),
    isCurrent: false, // enriched below
  })));
});

// ── Revoke a session ───────────────────────────────────────────────────────────

router.delete("/auth/sessions/:id", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const userId = req.user!.userId;
  const sessionId = parseInt(req.params.id, 10);

  if (isNaN(sessionId)) {
    res.status(400).json({ error: "Invalid session id" });
    return;
  }

  const [session] = await db
    .select()
    .from(sessionsTable)
    .where(and(eq(sessionsTable.id, sessionId), eq(sessionsTable.userId, userId)));

  if (!session) {
    res.status(404).json({ error: "Session not found" });
    return;
  }

  await db
    .update(sessionsTable)
    .set({ isActive: false })
    .where(eq(sessionsTable.id, sessionId));

  res.sendStatus(204);
});

// ── Revoke all other sessions ──────────────────────────────────────────────────

router.delete("/auth/sessions", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const userId = req.user!.userId;
  const currentSessionId = req.headers["x-session-id"] ? parseInt(req.headers["x-session-id"] as string, 10) : null;

  const conditions = [eq(sessionsTable.userId, userId), eq(sessionsTable.isActive, true)];

  const sessions = await db.select({ id: sessionsTable.id }).from(sessionsTable).where(and(...conditions));

  for (const s of sessions) {
    if (s.id !== currentSessionId) {
      await db.update(sessionsTable).set({ isActive: false }).where(eq(sessionsTable.id, s.id));
    }
  }

  res.sendStatus(204);
});

export default router;
