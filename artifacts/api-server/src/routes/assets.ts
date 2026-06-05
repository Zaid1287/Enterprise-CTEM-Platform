import { Router } from "express";
import { eq, and, ilike, sql, inArray } from "drizzle-orm";
import { db, assetsTable, usersTable, findingsTable, riskScoresTable } from "@workspace/db";
import {
  CreateAssetBody, GetAssetParams, UpdateAssetParams, UpdateAssetBody,
  DeleteAssetParams, VerifyAssetParams, VerifyAssetBody, CheckAssetVerificationParams,
  ListAssetsQueryParams,
} from "@workspace/api-zod";
import { requireAuth, type AuthenticatedRequest } from "../lib/auth";
import { logAudit } from "../lib/audit";
import crypto from "crypto";
import dns from "dns/promises";
import multer from "multer";
import path from "path";
import fs from "fs";

const router = Router();

const EVIDENCE_DIR = path.join(process.cwd(), "evidence");
if (!fs.existsSync(EVIDENCE_DIR)) fs.mkdirSync(EVIDENCE_DIR, { recursive: true });

const upload = multer({
  storage: multer.diskStorage({
    destination: (_req, _file, cb) => cb(null, EVIDENCE_DIR),
    filename: (_req, file, cb) => {
      const unique = `${Date.now()}-${crypto.randomBytes(4).toString("hex")}`;
      cb(null, `${unique}-${file.originalname.replace(/[^a-zA-Z0-9._-]/g, "_")}`);
    },
  }),
  limits: { fileSize: 20 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    const allowed = ["image/png", "image/jpeg", "image/gif", "image/webp",
      "application/pdf", "text/plain", "application/zip",
      "video/mp4", "video/webm"];
    cb(null, allowed.includes(file.mimetype));
  },
});

async function enrichAssets(assets: (typeof assetsTable.$inferSelect)[]) {
  if (assets.length === 0) return [];

  const userIds = new Set<number>();
  for (const a of assets) {
    if (a.assignedClientId) userIds.add(a.assignedClientId);
    if (a.assignedAccountManagerId) userIds.add(a.assignedAccountManagerId);
  }
  const userMap = new Map<number, string>();
  if (userIds.size > 0) {
    const ids = [...userIds];
    const users = await db
      .select({ id: usersTable.id, firstName: usersTable.firstName, lastName: usersTable.lastName })
      .from(usersTable)
      .where(sql`${usersTable.id} = ANY(ARRAY[${sql.join(ids.map(id => sql`${id}`), sql`, `)}]::int[])`);
    for (const u of users) userMap.set(u.id, `${u.firstName} ${u.lastName}`);
  }

  const assetIds = assets.map(a => a.id);

  // Fetch finding counts grouped by asset
  const findingRows = await db
    .select({
      assetId: findingsTable.assetId,
      total: sql<number>`count(*)::int`,
      open: sql<number>`count(*) filter (where ${findingsTable.status} = 'open')::int`,
      critical: sql<number>`count(*) filter (where ${findingsTable.severity} = 'critical')::int`,
      high: sql<number>`count(*) filter (where ${findingsTable.severity} = 'high')::int`,
    })
    .from(findingsTable)
    .where(inArray(findingsTable.assetId, assetIds))
    .groupBy(findingsTable.assetId);

  const findingMap = new Map(findingRows.map(r => [r.assetId, r]));

  // Fetch risk scores
  const riskRows = await db
    .select({ assetId: riskScoresTable.assetId, score: riskScoresTable.score, level: riskScoresTable.level })
    .from(riskScoresTable)
    .where(inArray(riskScoresTable.assetId, assetIds));
  const riskMap = new Map(riskRows.map(r => [r.assetId, r]));

  return assets.map(a => toAssetResponse(a, userMap, findingMap, riskMap));
}

function toAssetResponse(
  a: typeof assetsTable.$inferSelect,
  userMap?: Map<number, string>,
  findingMap?: Map<number, { total: number; open: number; critical: number; high: number }>,
  riskMap?: Map<number, { score: number; level: string }>,
) {
  const findings = findingMap?.get(a.id);
  const risk = riskMap?.get(a.id);
  return {
    id: a.id,
    tenantId: a.tenantId,
    name: a.name,
    type: a.type,
    value: a.value,
    verificationStatus: a.verificationStatus,
    verificationToken: a.verificationToken,
    riskLevel: risk?.level ?? a.riskLevel,
    riskScore: risk?.score ?? null,
    tags: a.tags ?? [],
    description: a.description,
    ipAddress: a.ipAddress,
    port: a.port,
    isActive: a.isActive,
    assignedClientId: a.assignedClientId ?? null,
    assignedClientName: (a.assignedClientId && userMap) ? (userMap.get(a.assignedClientId) ?? null) : null,
    assignedAccountManagerId: a.assignedAccountManagerId ?? null,
    assignedAccountManagerName: (a.assignedAccountManagerId && userMap) ? (userMap.get(a.assignedAccountManagerId) ?? null) : null,
    lastScannedAt: a.lastScannedAt?.toISOString() ?? null,
    createdAt: a.createdAt.toISOString(),
    vulnerabilities: {
      total: findings?.total ?? 0,
      open: findings?.open ?? 0,
      critical: findings?.critical ?? 0,
      high: findings?.high ?? 0,
    },
  };
}

router.get("/assets", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const query = ListAssetsQueryParams.safeParse(req.query);
  const filters = [eq(assetsTable.tenantId, req.user!.tenantId)];
  if (req.user!.role === "client") {
    filters.push(eq(assetsTable.assignedClientId, req.user!.userId));
  }
  if (query.success) {
    if (query.data.type) filters.push(eq(assetsTable.type, query.data.type));
    if (query.data.verificationStatus) filters.push(eq(assetsTable.verificationStatus, query.data.verificationStatus));
    if (query.data.search) filters.push(ilike(assetsTable.name, `%${query.data.search}%`));
  }
  // riskLevel filter (not in generated schema, read from raw query)
  if (req.query.riskLevel) {
    filters.push(eq(assetsTable.riskLevel, req.query.riskLevel as string));
  }
  const assets = await db.select().from(assetsTable).where(and(...filters));
  res.json(await enrichAssets(assets));
});

router.post("/assets", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const parsed = CreateAssetBody.safeParse(req.body);
  if (!parsed.success) { res.status(400).json(parsed.error.issues); return; }
  const { assignedClientId, assignedAccountManagerId, ...rest } = parsed.data as any;

  // For client role: auto-assign to themselves
  const clientId = req.user!.role === "client" ? req.user!.userId : (assignedClientId ?? null);

  const [asset] = await db.insert(assetsTable).values({
    ...rest,
    tenantId: req.user!.tenantId,
    assignedClientId: clientId,
    assignedAccountManagerId: req.user!.role === "client" ? null : (assignedAccountManagerId ?? null),
    verificationStatus: "unverified",
  }).returning();
  await logAudit(req.user!, "create_asset", "asset", asset.id);
  const [enriched] = await enrichAssets([asset]);
  res.status(201).json(enriched);
});

router.get("/assets/:assetId", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const params = GetAssetParams.safeParse(req.params);
  if (!params.success) { res.status(400).json({ error: params.error.message }); return; }
  const filters = [eq(assetsTable.id, params.data.assetId), eq(assetsTable.tenantId, req.user!.tenantId)];
  if (req.user!.role === "client") {
    filters.push(eq(assetsTable.assignedClientId, req.user!.userId));
  }
  const [asset] = await db.select().from(assetsTable).where(and(...filters));
  if (!asset) { res.status(404).json({ error: "Asset not found" }); return; }
  const [enriched] = await enrichAssets([asset]);
  res.json(enriched);
});

router.patch("/assets/:assetId", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const params = UpdateAssetParams.safeParse(req.params);
  if (!params.success) { res.status(400).json({ error: params.error.message }); return; }
  const parsed = UpdateAssetBody.safeParse(req.body);
  if (!parsed.success) { res.status(400).json(parsed.error.issues); return; }

  const updateData: any = { ...parsed.data };
  // Clients cannot change assignment fields
  if (req.user!.role === "client") {
    delete updateData.assignedClientId;
    delete updateData.assignedAccountManagerId;
  }

  const [asset] = await db.update(assetsTable).set(updateData)
    .where(and(eq(assetsTable.id, params.data.assetId), eq(assetsTable.tenantId, req.user!.tenantId)))
    .returning();
  if (!asset) { res.status(404).json({ error: "Asset not found" }); return; }
  await logAudit(req.user!, "update_asset", "asset", asset.id);
  const [enriched] = await enrichAssets([asset]);
  res.json(enriched);
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

// Generate a unique DNS TXT token for an asset (client-friendly)
router.post("/assets/:assetId/verify", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const params = VerifyAssetParams.safeParse(req.params);
  if (!params.success) { res.status(400).json({ error: params.error.message }); return; }
  const body = VerifyAssetBody.safeParse(req.body);
  if (!body.success) { res.status(400).json({ error: body.error.message }); return; }

  // Fetch existing token or generate a new one
  const [existing] = await db.select().from(assetsTable)
    .where(and(eq(assetsTable.id, params.data.assetId), eq(assetsTable.tenantId, req.user!.tenantId)));
  if (!existing) { res.status(404).json({ error: "Asset not found" }); return; }

  let token = existing.verificationToken;
  if (!token || !token.startsWith("ctem-verify-")) {
    token = `ctem-verify-${crypto.randomBytes(16).toString("hex")}`;
    await db.update(assetsTable)
      .set({ verificationToken: token, verificationStatus: "pending" })
      .where(and(eq(assetsTable.id, params.data.assetId), eq(assetsTable.tenantId, req.user!.tenantId)));
  } else if (existing.verificationStatus === "unverified") {
    await db.update(assetsTable)
      .set({ verificationStatus: "pending" })
      .where(and(eq(assetsTable.id, params.data.assetId), eq(assetsTable.tenantId, req.user!.tenantId)));
  }

  const methodInstructions: Record<string, string> = {
    dns_txt: `Add a DNS TXT record to your domain with value: ${token}`,
    email: `Click the verification link sent to admin@<your-domain>`,
    http_file: `Create a file at /.well-known/ctem-verification.txt with content: ${token}`,
    cloud: `Add tag ctem-verification=${token} to the cloud resource`,
  };

  res.json({
    method: body.data.method,
    challenge: token,
    instructions: methodInstructions[body.data.method] ?? `Use token: ${token}`,
    txtRecord: {
      type: "TXT",
      host: "_ctem-challenge",
      value: token,
      ttl: 300,
    },
  });
});

// Check DNS TXT record and mark verified if found
router.post("/assets/:assetId/verify/check", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const params = CheckAssetVerificationParams.safeParse(req.params);
  if (!params.success) { res.status(400).json({ error: params.error.message }); return; }

  const [asset] = await db.select().from(assetsTable)
    .where(and(eq(assetsTable.id, params.data.assetId), eq(assetsTable.tenantId, req.user!.tenantId)));
  if (!asset) { res.status(404).json({ error: "Asset not found" }); return; }

  const token = asset.verificationToken;

  // If asset is a domain/subdomain/url, do real DNS TXT lookup
  if (token && (asset.type === "domain" || asset.type === "subdomain" || asset.type === "url")) {
    const domain = asset.value.replace(/^https?:\/\//, "").split("/")[0].split(":")[0];
    try {
      const records = await dns.resolveTxt(`_ctem-challenge.${domain}`);
      const flat = records.flat();
      const found = flat.some(r => r === token);
      if (found) {
        await db.update(assetsTable)
          .set({ verificationStatus: "verified" })
          .where(eq(assetsTable.id, params.data.assetId));
        await logAudit(req.user!, "verify_asset", "asset", params.data.assetId);
        res.json({ verified: true, message: "DNS TXT record found. Asset ownership verified." });
      } else {
        res.json({ verified: false, message: `TXT record not found yet. Expected: ${token} on _ctem-challenge.${domain}` });
      }
      return;
    } catch {
      res.json({ verified: false, message: `Could not resolve DNS for _ctem-challenge.${domain}. Make sure the TXT record is added and DNS has propagated (may take up to 24h).` });
      return;
    }
  }

  // Non-domain assets: allow manual verification by admin/account_manager only
  if (req.user!.role === "client") {
    res.status(403).json({ error: "Only domain assets can be verified via TXT record" });
    return;
  }
  await db.update(assetsTable)
    .set({ verificationStatus: "verified" })
    .where(and(eq(assetsTable.id, params.data.assetId), eq(assetsTable.tenantId, req.user!.tenantId)));
  await logAudit(req.user!, "verify_asset", "asset", params.data.assetId);
  res.json({ verified: true, message: "Asset ownership successfully verified" });
});

// Upload evidence files for an asset
router.post("/assets/:assetId/evidence", requireAuth, upload.array("files", 10), async (req: AuthenticatedRequest, res): Promise<void> => {
  const assetId = parseInt(req.params.assetId, 10);
  if (!req.files || (req.files as Express.Multer.File[]).length === 0) {
    res.status(400).json({ error: "No files uploaded" }); return;
  }
  const files = (req.files as Express.Multer.File[]).map(f => ({
    filename: f.filename,
    originalName: f.originalname,
    size: f.size,
    mimetype: f.mimetype,
    url: `/api/assets/${assetId}/evidence/${f.filename}`,
  }));
  res.json({ uploaded: files });
});

// Serve evidence files
router.get("/assets/:assetId/evidence/:filename", requireAuth, (req: AuthenticatedRequest, res): void => {
  const filename = path.basename(req.params.filename);
  const filePath = path.join(EVIDENCE_DIR, filename);
  if (!fs.existsSync(filePath)) { res.status(404).json({ error: "File not found" }); return; }
  res.sendFile(filePath);
});

export default router;
