import { Router } from "express";
import { eq, and, desc } from "drizzle-orm";
import { db, scanSuppressionsTable, assetsTable } from "@workspace/db";
import { requireAuth, type AuthenticatedRequest } from "../lib/auth";
import { logAudit } from "../lib/audit";

const router = Router();

// ── List suppressions ────────────────────────────────────────────────────────
router.get("/suppressions", requireAuth, async (req, res) => {
  const { tenantId } = (req as AuthenticatedRequest).user;
  try {
    const rows = await db
      .select({
        id: scanSuppressionsTable.id,
        tenantId: scanSuppressionsTable.tenantId,
        assetId: scanSuppressionsTable.assetId,
        assetName: assetsTable.name,
        matchType: scanSuppressionsTable.matchType,
        pattern: scanSuppressionsTable.pattern,
        severity: scanSuppressionsTable.severity,
        note: scanSuppressionsTable.note,
        createdByUserId: scanSuppressionsTable.createdByUserId,
        createdAt: scanSuppressionsTable.createdAt,
      })
      .from(scanSuppressionsTable)
      .leftJoin(assetsTable, eq(assetsTable.id, scanSuppressionsTable.assetId))
      .where(eq(scanSuppressionsTable.tenantId, tenantId))
      .orderBy(desc(scanSuppressionsTable.createdAt));

    res.json(rows.map(r => ({ ...r, createdAt: r.createdAt.toISOString() })));
  } catch (err) {
    res.status(500).json({ error: "Failed to load suppressions" });
  }
});

// ── Delete a suppression ─────────────────────────────────────────────────────
router.delete("/suppressions/:id", requireAuth, async (req, res) => {
  const { tenantId, userId } = (req as AuthenticatedRequest).user;
  const id = parseInt(req.params.id, 10);
  if (isNaN(id)) { res.status(400).json({ error: "Invalid id" }); return; }

  const existing = await db
    .select({ id: scanSuppressionsTable.id })
    .from(scanSuppressionsTable)
    .where(and(eq(scanSuppressionsTable.id, id), eq(scanSuppressionsTable.tenantId, tenantId)))
    .then(r => r[0]);

  if (!existing) { res.status(404).json({ error: "Not found" }); return; }

  await db.delete(scanSuppressionsTable).where(eq(scanSuppressionsTable.id, id));
  await logAudit(db, { tenantId, userId: userId as any, action: "suppression.delete", resourceType: "scan_suppression", resourceId: String(id), ip: req.ip ?? "" });
  res.json({ success: true });
});

export default router;
