import { Router } from "express";
import { eq, asc } from "drizzle-orm";
import { db, cdnWhitelistTable } from "@workspace/db";
import { requireAuth, requireRole, type AuthenticatedRequest } from "../lib/auth";
import { cidrToRange } from "../lib/cidrUtils";
import { logger } from "../lib/logger";

const router = Router();

// ── GET /cdn-whitelist ────────────────────────────────────────────────────────
// All CDN-whitelist endpoints are super_admin only — applied per-route so this
// middleware does NOT intercept requests destined for other routers (e.g. aiMapper).
router.get("/cdn-whitelist", requireAuth, requireRole("super_admin"), async (_req: AuthenticatedRequest, res): Promise<void> => {
  try {
    const rows = await db
      .select()
      .from(cdnWhitelistTable)
      .orderBy(asc(cdnWhitelistTable.isBuiltIn), asc(cdnWhitelistTable.label), asc(cdnWhitelistTable.cidr));
    res.json(rows);
  } catch (err) {
    logger.error({ err }, "cdn-whitelist list error");
    res.status(500).json({ error: "Failed to load CDN whitelist" });
  }
});

// ── POST /cdn-whitelist ───────────────────────────────────────────────────────
router.post("/cdn-whitelist", requireAuth, requireRole("super_admin"), async (req: AuthenticatedRequest, res): Promise<void> => {
  const { label, cidr, description } = req.body ?? {};
  if (!label || !cidr) {
    res.status(400).json({ error: "label and cidr are required" });
    return;
  }
  const range = cidrToRange(String(cidr));
  if (!range) {
    res.status(400).json({ error: "Invalid CIDR notation — use format x.x.x.x/prefix (e.g. 151.101.0.0/16)" });
    return;
  }
  try {
    const [row] = await db.insert(cdnWhitelistTable).values({
      label:       String(label).trim(),
      cidr:        String(cidr).trim(),
      ipStart:     range.start,
      ipEnd:       range.end,
      description: description ? String(description).trim() : null,
      isActive:    true,
      isBuiltIn:   false,
    }).returning();
    logger.info({ id: row!.id, cidr, label }, "CDN whitelist entry created");
    res.status(201).json(row);
  } catch (err) {
    logger.error({ err }, "cdn-whitelist create error");
    res.status(500).json({ error: "Failed to create CDN whitelist entry" });
  }
});

// ── PATCH /cdn-whitelist/:id ──────────────────────────────────────────────────
router.patch("/cdn-whitelist/:id", requireAuth, requireRole("super_admin"), async (req: AuthenticatedRequest, res): Promise<void> => {
  const id = parseInt(req.params.id as string, 10);
  if (isNaN(id)) { res.status(400).json({ error: "Invalid id" }); return; }

  const existing = await db.select().from(cdnWhitelistTable).where(eq(cdnWhitelistTable.id, id));
  if (!existing.length) { res.status(404).json({ error: "Not found" }); return; }

  const updates: Partial<typeof cdnWhitelistTable.$inferInsert> = {};

  if (req.body?.label !== undefined) updates.label = String(req.body.label).trim();
  if (req.body?.description !== undefined) updates.description = req.body.description ? String(req.body.description).trim() : null;
  if (req.body?.isActive !== undefined) updates.isActive = Boolean(req.body.isActive);

  if (req.body?.cidr !== undefined) {
    const range = cidrToRange(String(req.body.cidr));
    if (!range) {
      res.status(400).json({ error: "Invalid CIDR notation" });
      return;
    }
    updates.cidr    = String(req.body.cidr).trim();
    updates.ipStart = range.start;
    updates.ipEnd   = range.end;
  }

  try {
    const [row] = await db.update(cdnWhitelistTable).set(updates).where(eq(cdnWhitelistTable.id, id)).returning();
    logger.info({ id }, "CDN whitelist entry updated");
    res.json(row);
  } catch (err) {
    logger.error({ err }, "cdn-whitelist update error");
    res.status(500).json({ error: "Failed to update CDN whitelist entry" });
  }
});

// ── DELETE /cdn-whitelist/:id ─────────────────────────────────────────────────
router.delete("/cdn-whitelist/:id", requireAuth, requireRole("super_admin"), async (req: AuthenticatedRequest, res): Promise<void> => {
  const id = parseInt(req.params.id as string, 10);
  if (isNaN(id)) { res.status(400).json({ error: "Invalid id" }); return; }

  const existing = await db.select().from(cdnWhitelistTable).where(eq(cdnWhitelistTable.id, id));
  if (!existing.length) { res.status(404).json({ error: "Not found" }); return; }

  try {
    await db.delete(cdnWhitelistTable).where(eq(cdnWhitelistTable.id, id));
    logger.info({ id, label: existing[0]!.label, cidr: existing[0]!.cidr }, "CDN whitelist entry deleted");
    res.json({ success: true });
  } catch (err) {
    logger.error({ err }, "cdn-whitelist delete error");
    res.status(500).json({ error: "Failed to delete CDN whitelist entry" });
  }
});

export default router;
