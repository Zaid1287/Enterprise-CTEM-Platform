import { Router } from "express";
import { eq, and, desc } from "drizzle-orm";
import { db, brandThreatScansTable, brandThreatResultsTable } from "@workspace/db";
import { requireAuth, type AuthenticatedRequest } from "../lib/auth";
import { runBrandThreatScan } from "../lib/brandThreatRunner";

const router = Router();

function toScanResponse(s: typeof brandThreatScansTable.$inferSelect) {
  return {
    ...s,
    createdAt: s.createdAt.toISOString(),
    completedAt: s.completedAt ? s.completedAt.toISOString() : null,
  };
}

// ── GET /brand-threats ────────────────────────────────────────────────────────
router.get("/brand-threats", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const scans = await db.select().from(brandThreatScansTable)
    .where(eq(brandThreatScansTable.tenantId, req.user!.tenantId))
    .orderBy(desc(brandThreatScansTable.createdAt));
  res.json(scans.map(toScanResponse));
});

// ── POST /brand-threats ───────────────────────────────────────────────────────
router.post("/brand-threats", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const raw = String(req.body?.domain ?? "").trim().toLowerCase()
    .replace(/^https?:\/\//, "").replace(/^www\./, "").split("/")[0].split("?")[0];
  if (!raw || !/^[a-z0-9]([a-z0-9.-]*[a-z0-9])?\.[a-z]{2,}$/.test(raw)) {
    res.status(400).json({ error: "Invalid domain. Expected format: example.com" }); return;
  }
  const [scan] = await db.insert(brandThreatScansTable).values({
    tenantId: req.user!.tenantId,
    domain: raw,
    status: "pending",
  }).returning();
  setImmediate(() => { void runBrandThreatScan(scan.id, raw); });
  res.json(toScanResponse(scan));
});

// ── GET /brand-threats/:id ────────────────────────────────────────────────────
router.get("/brand-threats/:id", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const id = parseInt(String(req.params.id), 10);
  if (isNaN(id)) { res.status(400).json({ error: "Invalid ID" }); return; }
  const [scan] = await db.select().from(brandThreatScansTable)
    .where(and(eq(brandThreatScansTable.id, id), eq(brandThreatScansTable.tenantId, req.user!.tenantId)));
  if (!scan) { res.status(404).json({ error: "Scan not found" }); return; }
  const results = await db.select().from(brandThreatResultsTable)
    .where(eq(brandThreatResultsTable.scanId, id))
    .orderBy(desc(brandThreatResultsTable.riskScore));
  res.json({
    ...toScanResponse(scan),
    results: results.map(r => ({ ...r, createdAt: r.createdAt.toISOString() })),
  });
});

// ── DELETE /brand-threats/:id ─────────────────────────────────────────────────
router.delete("/brand-threats/:id", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const id = parseInt(String(req.params.id), 10);
  if (isNaN(id)) { res.status(400).json({ error: "Invalid ID" }); return; }
  const [existing] = await db.select({ id: brandThreatScansTable.id }).from(brandThreatScansTable)
    .where(and(eq(brandThreatScansTable.id, id), eq(brandThreatScansTable.tenantId, req.user!.tenantId)));
  if (!existing) { res.status(404).json({ error: "Scan not found" }); return; }
  await db.delete(brandThreatScansTable).where(eq(brandThreatScansTable.id, id));
  res.json({ success: true });
});

export default router;
