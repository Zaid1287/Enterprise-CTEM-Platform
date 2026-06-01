import { Router } from "express";
import { eq, and, ilike, sql } from "drizzle-orm";
import { db, assetsTable } from "@workspace/db";
import {
  CreateAssetBody, GetAssetParams, UpdateAssetParams, UpdateAssetBody,
  DeleteAssetParams, VerifyAssetParams, VerifyAssetBody, CheckAssetVerificationParams,
  ListAssetsQueryParams,
} from "@workspace/api-zod";
import { requireAuth, type AuthenticatedRequest } from "../lib/auth";
import { logAudit } from "../lib/audit";
import crypto from "crypto";

const router = Router();

function toAssetResponse(a: typeof assetsTable.$inferSelect) {
  return {
    id: a.id, tenantId: a.tenantId, name: a.name, type: a.type, value: a.value,
    verificationStatus: a.verificationStatus, riskLevel: a.riskLevel, tags: a.tags ?? [],
    description: a.description, ipAddress: a.ipAddress, port: a.port,
    isActive: a.isActive, lastScannedAt: a.lastScannedAt?.toISOString() ?? null,
    createdAt: a.createdAt.toISOString(),
  };
}

router.get("/assets", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const query = ListAssetsQueryParams.safeParse(req.query);
  const filters = [eq(assetsTable.tenantId, req.user!.tenantId)];
  if (query.success) {
    if (query.data.type) filters.push(eq(assetsTable.type, query.data.type));
    if (query.data.verificationStatus) filters.push(eq(assetsTable.verificationStatus, query.data.verificationStatus));
    if (query.data.search) filters.push(ilike(assetsTable.name, `%${query.data.search}%`));
  }
  const assets = await db.select().from(assetsTable).where(and(...filters));
  res.json(assets.map(toAssetResponse));
});

router.post("/assets", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const parsed = CreateAssetBody.safeParse(req.body);
  if (!parsed.success) { res.status(400).json({ error: parsed.error.message }); return; }
  const [asset] = await db.insert(assetsTable).values({
    ...parsed.data, tenantId: req.user!.tenantId,
  }).returning();
  await logAudit(req.user!, "create_asset", "asset", asset.id);
  res.status(201).json(toAssetResponse(asset));
});

router.get("/assets/:assetId", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const params = GetAssetParams.safeParse(req.params);
  if (!params.success) { res.status(400).json({ error: params.error.message }); return; }
  const [asset] = await db.select().from(assetsTable)
    .where(and(eq(assetsTable.id, params.data.assetId), eq(assetsTable.tenantId, req.user!.tenantId)));
  if (!asset) { res.status(404).json({ error: "Asset not found" }); return; }
  res.json(toAssetResponse(asset));
});

router.patch("/assets/:assetId", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const params = UpdateAssetParams.safeParse(req.params);
  if (!params.success) { res.status(400).json({ error: params.error.message }); return; }
  const parsed = UpdateAssetBody.safeParse(req.body);
  if (!parsed.success) { res.status(400).json({ error: parsed.error.message }); return; }
  const [asset] = await db.update(assetsTable).set(parsed.data)
    .where(and(eq(assetsTable.id, params.data.assetId), eq(assetsTable.tenantId, req.user!.tenantId)))
    .returning();
  if (!asset) { res.status(404).json({ error: "Asset not found" }); return; }
  await logAudit(req.user!, "update_asset", "asset", asset.id);
  res.json(toAssetResponse(asset));
});

router.delete("/assets/:assetId", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const params = DeleteAssetParams.safeParse(req.params);
  if (!params.success) { res.status(400).json({ error: params.error.message }); return; }
  const [asset] = await db.delete(assetsTable)
    .where(and(eq(assetsTable.id, params.data.assetId), eq(assetsTable.tenantId, req.user!.tenantId)))
    .returning();
  if (!asset) { res.status(404).json({ error: "Asset not found" }); return; }
  await logAudit(req.user!, "delete_asset", "asset", asset.id);
  res.sendStatus(204);
});

router.post("/assets/:assetId/verify", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const params = VerifyAssetParams.safeParse(req.params);
  if (!params.success) { res.status(400).json({ error: params.error.message }); return; }
  const body = VerifyAssetBody.safeParse(req.body);
  if (!body.success) { res.status(400).json({ error: body.error.message }); return; }

  const token = `ctem-verify-${crypto.randomBytes(16).toString("hex")}`;
  await db.update(assetsTable)
    .set({ verificationToken: token, verificationStatus: "pending" })
    .where(and(eq(assetsTable.id, params.data.assetId), eq(assetsTable.tenantId, req.user!.tenantId)));

  const methodInstructions: Record<string, string> = {
    dns_txt: `Add a TXT record to your DNS with value: ${token}`,
    email: `Click the verification link sent to admin@<your-domain>`,
    http_file: `Create a file at /.well-known/ctem-verification.txt with content: ${token}`,
    cloud: `Add tag ctem-verification=${token} to the cloud resource`,
  };

  res.json({
    method: body.data.method,
    challenge: token,
    instructions: methodInstructions[body.data.method] ?? `Use token: ${token}`,
  });
});

router.post("/assets/:assetId/verify/check", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const params = CheckAssetVerificationParams.safeParse(req.params);
  if (!params.success) { res.status(400).json({ error: params.error.message }); return; }

  // Simulate verification check — in production this would do actual DNS/HTTP lookups
  await db.update(assetsTable)
    .set({ verificationStatus: "verified" })
    .where(and(eq(assetsTable.id, params.data.assetId), eq(assetsTable.tenantId, req.user!.tenantId)));

  res.json({ verified: true, message: "Asset ownership successfully verified" });
});

export default router;
