import { Router } from "express";
import { eq, and, desc } from "drizzle-orm";
import { db, screenshotsTable, assetsTable } from "@workspace/db";
import { requireAuth, denyExternalMembers, type AuthenticatedRequest } from "../lib/auth";
import { captureScreenshots } from "../lib/screenshotEngine";

const router = Router();
router.use(denyExternalMembers);

// GET /assets/:assetId/screenshots
router.get("/assets/:assetId/screenshots", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const assetId  = parseInt(req.params.assetId as string, 10);
  const tenantId = req.user!.tenantId;

  const asset = await db.select({ id: assetsTable.id })
    .from(assetsTable).where(and(eq(assetsTable.id, assetId), eq(assetsTable.tenantId, tenantId))).then(r => r[0]);
  if (!asset) { res.status(404).json({ message: "Asset not found" }); return; }

  const rows = await db.select().from(screenshotsTable)
    .where(and(eq(screenshotsTable.assetId, assetId), eq(screenshotsTable.tenantId, tenantId)))
    .orderBy(desc(screenshotsTable.capturedAt));

  res.json(rows);
});

// POST /assets/:assetId/screenshot-scan
router.post("/assets/:assetId/screenshot-scan", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const assetId  = parseInt(req.params.assetId as string, 10);
  const tenantId = req.user!.tenantId;

  const asset = await db.select().from(assetsTable)
    .where(and(eq(assetsTable.id, assetId), eq(assetsTable.tenantId, tenantId))).then(r => r[0]);
  if (!asset) { res.status(404).json({ message: "Asset not found" }); return; }

  const captures = await captureScreenshots(asset.value, 90000);

  if (captures.length > 0) {
    // Replace all previous screenshots for this asset
    await db.delete(screenshotsTable)
      .where(and(eq(screenshotsTable.assetId, assetId), eq(screenshotsTable.tenantId, tenantId)));

    await db.insert(screenshotsTable).values(
      captures.map(c => ({
        tenantId,
        assetId,
        scanId:         null,
        url:            c.url,
        pageType:       c.pageType,
        screenshotData: c.screenshotData,
        title:          c.title || null,
        statusCode:     c.statusCode || null,
        findings:       c.findings,
      }))
    );
  }

  const rows = await db.select().from(screenshotsTable)
    .where(and(eq(screenshotsTable.assetId, assetId), eq(screenshotsTable.tenantId, tenantId)))
    .orderBy(desc(screenshotsTable.capturedAt));

  res.json({ screenshots: rows, capturedAt: new Date().toISOString() });
});

export default router;
