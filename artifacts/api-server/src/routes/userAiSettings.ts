import { Router } from "express";
import { eq, and } from "drizzle-orm";
import { db, userAiSettingsTable } from "@workspace/db";
import { requireAuth, denyExternalMembers, type AuthenticatedRequest } from "../lib/auth";

const router = Router();
router.use(denyExternalMembers);

const ALLOWED_PROVIDERS = ["openai", "gemini", "anthropic", "openrouter", "ollama"] as const;

router.get("/me/ai-settings", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const settings = await db
    .select()
    .from(userAiSettingsTable)
    .where(eq(userAiSettingsTable.userId, req.user!.userId));

  // Return masked keys (show only last 6 chars)
  const masked = settings.map(s => ({
    id: s.id,
    provider: s.provider,
    apiKey: s.apiKey ? `${"•".repeat(Math.max(0, s.apiKey.length - 6))}${s.apiKey.slice(-6)}` : "",
    baseUrl: s.baseUrl,
    hasKey: !!s.apiKey,
    updatedAt: s.updatedAt.toISOString(),
  }));

  res.json(masked);
});

router.put("/me/ai-settings/:provider", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const { provider } = req.params;
  if (!ALLOWED_PROVIDERS.includes(provider as any)) {
    res.status(400).json({ error: "Invalid provider" });
    return;
  }

  const { apiKey, baseUrl } = req.body as { apiKey?: string; baseUrl?: string };
  if (apiKey === undefined) {
    res.status(400).json({ error: "apiKey is required" });
    return;
  }

  const [existing] = await db
    .select()
    .from(userAiSettingsTable)
    .where(and(eq(userAiSettingsTable.userId, req.user!.userId), eq(userAiSettingsTable.provider, provider)));

  if (existing) {
    await db
      .update(userAiSettingsTable)
      .set({ apiKey, baseUrl: baseUrl ?? null })
      .where(eq(userAiSettingsTable.id, existing.id));
  } else {
    await db.insert(userAiSettingsTable).values({
      userId: req.user!.userId,
      provider,
      apiKey,
      baseUrl: baseUrl ?? null,
    });
  }

  res.json({ ok: true, provider });
});

router.delete("/me/ai-settings/:provider", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const { provider } = req.params;
  await db
    .delete(userAiSettingsTable)
    .where(and(eq(userAiSettingsTable.userId, req.user!.userId), eq(userAiSettingsTable.provider, provider)));
  res.sendStatus(204);
});

/** Internal helper — get a user's real API key for a given provider */
export async function getUserApiKey(userId: number, provider: string): Promise<{ apiKey: string; baseUrl?: string | null } | null> {
  const [row] = await db
    .select()
    .from(userAiSettingsTable)
    .where(and(eq(userAiSettingsTable.userId, userId), eq(userAiSettingsTable.provider, provider)));
  return row ? { apiKey: row.apiKey, baseUrl: row.baseUrl } : null;
}

export default router;
