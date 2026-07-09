import { Router } from "express";
import { eq, and, ilike, sql, inArray, desc, isNull, or, ne } from "drizzle-orm";
import { getAmClientTenantIds } from "../lib/amScoping";
import { getPrivilegedTenantIds } from "../lib/tenantScoping";
import {
  db, assetsTable, usersTable, findingsTable, findingCommentsTable, riskScoresTable,
  technologyDetectionsTable, scanAssetResultsTable, assetGroupMembersTable, discoveryResultsTable,
  tenantsTable, brandThreatScansTable, externalMemberAssetsTable,
} from "@workspace/db";
import {
  CreateAssetBody, GetAssetParams, UpdateAssetParams, UpdateAssetBody,
  DeleteAssetParams, VerifyAssetParams, VerifyAssetBody, CheckAssetVerificationParams,
  ListAssetsQueryParams,
} from "@workspace/api-zod";
import { requireAuth, type AuthenticatedRequest } from "../lib/auth";
import { logAudit } from "../lib/audit";
import { detectTechnologies } from "../lib/techDetector";
import { sendEmail, verificationEmailHtml } from "../lib/email";
import crypto from "crypto";
import dns from "dns/promises";
import multer from "multer";
import path from "path";
import fs from "fs";

function getPlatformBaseUrl(req: { protocol: string; get: (h: string) => string | undefined }): string {
  const domains = process.env.REPLIT_DOMAINS;
  if (domains) return `https://${domains.split(",")[0].trim()}`;
  return `${req.protocol}://${req.get("host") ?? "localhost:80"}`;
}

function normalizeDomain(v: string): string {
  return v.toLowerCase()
    .replace(/^https?:\/\//, "")
    .replace(/^www\./, "")
    .split("/")[0]!.split("?")[0]!.split(":")[0]!;
}

/**
 * When an admin/super_admin verifies a domain, automatically mark all other
 * assets with the same domain value as verified across all tenants.
 * This keeps platform tenant and client tenant assets in sync so neither
 * remains blocked from scanning after the admin proves domain ownership.
 * Returns the number of additional assets that were synced.
 */
async function syncDomainVerification(verifiedAssetId: number, assetValue: string): Promise<number> {
  const normalized = normalizeDomain(assetValue);
  if (!normalized) return 0;
  const synced = await db.update(assetsTable)
    .set({ verificationStatus: "verified", verificationToken: null })
    .where(and(
      sql`LOWER(REGEXP_REPLACE(${assetsTable.value}, '^(https?://)?(www\\.)?', '')) = ${normalized}`,
      ne(assetsTable.id, verifiedAssetId),
      ne(assetsTable.verificationStatus, "verified")
    ))
    .returning({ id: assetsTable.id });
  return synced.length;
}

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

type BrandThreatSummary = {
  scanId: number;
  phishingRisk: string;
  liveCount: number;
  phishingCount: number;
  dataLeakCount: number;
  brandAbuseCount: number;
};

async function enrichAssets(assets: (typeof assetsTable.$inferSelect)[]) {
  if (assets.length === 0) return [];

  // Fetch tenant names for SA cross-tenant view
  const tenantIds = [...new Set(assets.map(a => a.tenantId).filter((id): id is number => id != null))];
  const tenantMap = new Map<number, string>();
  if (tenantIds.length > 0) {
    const tenantRows = await db
      .select({ id: tenantsTable.id, name: tenantsTable.name })
      .from(tenantsTable)
      .where(inArray(tenantsTable.id, tenantIds));
    for (const t of tenantRows) tenantMap.set(t.id, t.name);
  }

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

  // Fetch brand threat scan summaries — match on normalized domain, latest completed scan per domain
  const btMap = new Map<string, BrandThreatSummary>();
  if (tenantIds.length > 0) {
    const btScans = await db
      .select({
        id: brandThreatScansTable.id,
        tenantId: brandThreatScansTable.tenantId,
        domain: brandThreatScansTable.domain,
        phishingRisk: brandThreatScansTable.phishingRisk,
        liveCount: brandThreatScansTable.liveCount,
        phishingCount: brandThreatScansTable.phishingCount,
        dataLeakCount: brandThreatScansTable.dataLeakCount,
        brandAbuseCount: brandThreatScansTable.brandAbuseCount,
      })
      .from(brandThreatScansTable)
      .where(and(
        inArray(brandThreatScansTable.tenantId, tenantIds),
        eq(brandThreatScansTable.status, "completed"),
      ))
      .orderBy(desc(brandThreatScansTable.createdAt));
    for (const scan of btScans) {
      const key = `${scan.tenantId}:${normalizeDomain(scan.domain)}`;
      if (!btMap.has(key)) {
        btMap.set(key, {
          scanId: scan.id,
          phishingRisk: scan.phishingRisk,
          liveCount: scan.liveCount,
          phishingCount: scan.phishingCount,
          dataLeakCount: scan.dataLeakCount,
          brandAbuseCount: scan.brandAbuseCount,
        });
      }
    }
  }

  return assets.map(a => toAssetResponse(a, userMap, findingMap, riskMap, tenantMap, btMap));
}

/** WHERE clause for a single asset: SA can access any asset across all tenants. */
function assetAccessFilter(assetId: number, user: { tenantId: number; role: string }, amTenantIds?: number[]) {
  const byId = eq(assetsTable.id, assetId);
  if (user.role === "super_admin") return byId;
  if (user.role === "account_manager" && amTenantIds && amTenantIds.length > 0) {
    return and(byId, inArray(assetsTable.tenantId, amTenantIds))!;
  }
  return and(byId, eq(assetsTable.tenantId, user.tenantId))!;
}

function toAssetResponse(
  a: typeof assetsTable.$inferSelect,
  userMap?: Map<number, string>,
  findingMap?: Map<number, { total: number; open: number; critical: number; high: number }>,
  riskMap?: Map<number, { score: number; level: string }>,
  tenantMap?: Map<number, string>,
  btMap?: Map<string, BrandThreatSummary>,
) {
  const findings = findingMap?.get(a.id);
  const risk = riskMap?.get(a.id);
  const btKey = (a.tenantId && btMap) ? `${a.tenantId}:${normalizeDomain(a.value ?? "")}` : null;
  const brandThreat = btKey ? (btMap?.get(btKey) ?? null) : null;
  return {
    id: a.id,
    tenantId: a.tenantId,
    tenantName: (a.tenantId && tenantMap) ? (tenantMap.get(a.tenantId) ?? null) : null,
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
    metadata: (a as any).metadata ?? null,
    assignedClientId: a.assignedClientId ?? null,
    assignedClientName: (a.assignedClientId && userMap) ? (userMap.get(a.assignedClientId) ?? null) : null,
    assignedAccountManagerId: a.assignedAccountManagerId ?? null,
    assignedAccountManagerName: (a.assignedAccountManagerId && userMap) ? (userMap.get(a.assignedAccountManagerId) ?? null) : null,
    scanFrequency: a.scanFrequency ?? "manual",
    businessImpact: a.businessImpact ?? 5,
    lastScannedAt: a.lastScannedAt?.toISOString() ?? null,
    createdAt: a.createdAt.toISOString(),
    vulnerabilities: {
      total: findings?.total ?? 0,
      open: findings?.open ?? 0,
      critical: findings?.critical ?? 0,
      high: findings?.high ?? 0,
    },
    brandThreatSummary: brandThreat,
  };
}

router.get("/assets", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const query = ListAssetsQueryParams.safeParse(req.query);
  const role = req.user!.role;

  // External members see only assets explicitly granted to them via external_member_assets
  if (role === "vendor" || role === "employee" || role === "third_party") {
    const rows = await db.select({ assetId: externalMemberAssetsTable.assetId })
      .from(externalMemberAssetsTable)
      .where(eq(externalMemberAssetsTable.userId, req.user!.userId));
    if (rows.length === 0) { res.json([]); return; }
    const allowedIds = rows.map(r => r.assetId);
    const assets = await db.select().from(assetsTable).where(inArray(assetsTable.id, allowedIds));
    res.json(await enrichAssets(assets));
    return;
  }

  let tenantFilter;
  if (role === "account_manager") {
    const ids = await getAmClientTenantIds(req.user!.userId);
    if (ids.length === 0) { res.json([]); return; }
    tenantFilter = inArray(assetsTable.tenantId, ids);
  } else if (role === "super_admin" || role === "admin") {
    // SA/Admin see only their own platform tenant's assets.
    // Client-assigned assets live in the platform tenant with assignedClientId set —
    // no need to also query client tenants (which would produce duplicates).
    tenantFilter = eq(assetsTable.tenantId, req.user!.tenantId);
  } else if (role === "client") {
    // Clients see only their assigned assets — cross-tenant, no tenantId restriction
    tenantFilter = undefined;
  } else {
    tenantFilter = eq(assetsTable.tenantId, req.user!.tenantId);
  }
  const filters: ReturnType<typeof eq>[] = [];
  if (tenantFilter) filters.push(tenantFilter as any);
  if (role === "client") {
    filters.push(eq(assetsTable.assignedClientId, req.user!.userId) as any);
  }
  if (query.success) {
    if (query.data.type) filters.push(eq(assetsTable.type, query.data.type) as any);
    if (query.data.verificationStatus) filters.push(eq(assetsTable.verificationStatus, query.data.verificationStatus) as any);
    if (query.data.search) filters.push(ilike(assetsTable.name, `%${query.data.search}%`) as any);
  }
  // riskLevel filter (not in generated schema, read from raw query)
  if (req.query.riskLevel) {
    filters.push(eq(assetsTable.riskLevel, req.query.riskLevel as string) as any);
  }
  const assets = await db.select().from(assetsTable).where(filters.length ? and(...filters) : undefined);
  res.json(await enrichAssets(assets));
});

router.post("/assets", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  // External members cannot create assets
  const createRole = req.user!.role;
  if (createRole === "vendor" || createRole === "employee" || createRole === "third_party") {
    res.status(403).json({ error: "External members cannot create assets" }); return;
  }
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
    scanFrequency: (req.body.scanFrequency as string) ?? "manual",
  }).returning();
  await logAudit(req.user!, "create_asset", "asset", asset.id);
  const [enriched] = await enrichAssets([asset]);
  res.status(201).json(enriched);
});

router.get("/assets/:assetId", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const params = GetAssetParams.safeParse(req.params);
  if (!params.success) { res.status(400).json({ error: params.error.message }); return; }
  const role = req.user!.role;

  // External members: verify asset is in their allowed list
  if (role === "vendor" || role === "employee" || role === "third_party") {
    const [granted] = await db.select({ assetId: externalMemberAssetsTable.assetId })
      .from(externalMemberAssetsTable)
      .where(and(
        eq(externalMemberAssetsTable.userId, req.user!.userId),
        eq(externalMemberAssetsTable.assetId, params.data.assetId),
      ));
    if (!granted) { res.status(404).json({ error: "Asset not found" }); return; }
    const [asset] = await db.select().from(assetsTable).where(eq(assetsTable.id, params.data.assetId));
    if (!asset) { res.status(404).json({ error: "Asset not found" }); return; }
    const [enriched] = await enrichAssets([asset]);
    res.json(enriched);
    return;
  }

  const amTids = role === "account_manager" ? await getAmClientTenantIds(req.user!.userId) : undefined;
  const filters: ReturnType<typeof eq>[] = [assetAccessFilter(params.data.assetId, req.user!, amTids) as any];
  if (role === "client") {
    filters.push(eq(assetsTable.assignedClientId, req.user!.userId) as any);
  }
  const [asset] = await db.select().from(assetsTable).where(and(...filters));
  if (!asset) { res.status(404).json({ error: "Asset not found" }); return; }
  const [enriched] = await enrichAssets([asset]);
  res.json(enriched);
});

router.patch("/assets/:assetId", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const params = UpdateAssetParams.safeParse(req.params);
  if (!params.success) { res.status(400).json({ error: params.error.message }); return; }

  // Clients and external members cannot modify assets
  const patchAssetRole = req.user!.role;
  if (patchAssetRole === "client" || patchAssetRole === "vendor" || patchAssetRole === "employee" || patchAssetRole === "third_party") {
    res.status(403).json({ error: "Forbidden" }); return;
  }

  const parsed = UpdateAssetBody.safeParse(req.body);
  if (!parsed.success) { res.status(400).json(parsed.error.issues); return; }

  const updateData: any = { ...parsed.data };
  if (req.body.scanFrequency) updateData.scanFrequency = req.body.scanFrequency;

  // Only admin / super_admin / account_manager may set assignment fields; everyone else has them stripped
  const canAssign = patchAssetRole === "admin" || patchAssetRole === "super_admin" || patchAssetRole === "account_manager";
  if (!canAssign) {
    delete updateData.assignedClientId;
    delete updateData.assignedAccountManagerId;
  }

  // Load the target asset first (scoped to roles that can access it) so we can validate against ITS tenant
  const patchAmTids = patchAssetRole === "account_manager" ? await getAmClientTenantIds(req.user!.userId) : undefined;
  const [existingAsset] = await db.select({ id: assetsTable.id, tenantId: assetsTable.tenantId })
    .from(assetsTable).where(assetAccessFilter(params.data.assetId, req.user!, patchAmTids));
  if (!existingAsset) { res.status(404).json({ error: "Asset not found" }); return; }

  // Validate assignedClientId: must be role='client' AND same tenant as the asset being updated
  if (updateData.assignedClientId != null && typeof updateData.assignedClientId === "number") {
    const [targetUser] = await db.select({ id: usersTable.id, role: usersTable.role, tenantId: usersTable.tenantId })
      .from(usersTable).where(eq(usersTable.id, updateData.assignedClientId));
    if (!targetUser || targetUser.role !== "client" || targetUser.tenantId !== existingAsset.tenantId) {
      res.status(400).json({ error: "assignedClientId must refer to a client-role user within the same tenant as the asset" }); return;
    }
  }

  const [asset] = await db.update(assetsTable).set(updateData)
    .where(eq(assetsTable.id, existingAsset.id))
    .returning();
  if (!asset) { res.status(404).json({ error: "Asset not found" }); return; }
  await logAudit(req.user!, "update_asset", "asset", asset.id);
  const [enriched] = await enrichAssets([asset]);
  res.json(enriched);
});

router.delete("/assets/:assetId", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const params = DeleteAssetParams.safeParse(req.params);
  if (!params.success) { res.status(400).json({ error: params.error.message }); return; }

  // External members cannot delete assets
  const deleteAssetRole = req.user!.role;
  if (deleteAssetRole === "vendor" || deleteAssetRole === "employee" || deleteAssetRole === "third_party") {
    res.status(403).json({ error: "External members cannot delete assets" }); return;
  }

  const { assetId } = params.data;
  const tenantId = req.user!.tenantId;

  // Verify ownership before cascading
  const [asset] = await db.select().from(assetsTable)
    .where(and(eq(assetsTable.id, assetId), eq(assetsTable.tenantId, tenantId)));
  if (!asset) { res.status(404).json({ error: "Asset not found" }); return; }

  // 1. Delete finding comments → findings
  const assetFindings = await db.select({ id: findingsTable.id }).from(findingsTable)
    .where(and(eq(findingsTable.assetId, assetId), eq(findingsTable.tenantId, tenantId)));
  if (assetFindings.length > 0) {
    const fids = assetFindings.map(f => f.id);
    await db.delete(findingCommentsTable).where(inArray(findingCommentsTable.findingId, fids));
    await db.delete(findingsTable).where(inArray(findingsTable.id, fids));
  }
  // 2. Delete scan asset results
  await db.delete(scanAssetResultsTable).where(eq(scanAssetResultsTable.assetId, assetId));
  // 3. Remove from asset groups
  await db.delete(assetGroupMembersTable).where(eq(assetGroupMembersTable.assetId, assetId));
  // 4. Delete risk score (unique FK)
  await db.delete(riskScoresTable).where(eq(riskScoresTable.assetId, assetId));
  // 5. Delete discovery results
  await db.delete(discoveryResultsTable).where(eq(discoveryResultsTable.assetId, assetId));
  // 6. Delete asset (screenshots + technology_detections cascade via DB)
  await db.delete(assetsTable).where(eq(assetsTable.id, assetId));

  await logAudit(req.user!, "delete_asset", "asset", asset.id);
  res.sendStatus(204);
});

// ── Email confirm link (no auth — clicked from email inbox) ──────────────────
router.get("/assets/:assetId/verify/email-confirm", async (req, res): Promise<void> => {
  const assetId = parseInt(req.params.assetId, 10);
  const token = req.query.token as string | undefined;
  if (isNaN(assetId) || !token) {
    res.status(400).send(confirmHtml("error", "Invalid confirmation link."));
    return;
  }
  const [asset] = await db.select().from(assetsTable).where(eq(assetsTable.id, assetId));
  if (!asset || asset.verificationEmailToken !== token) {
    res.status(400).send(confirmHtml("error", "This confirmation link is invalid or has already been used."));
    return;
  }
  if (asset.verificationEmailExpiry && asset.verificationEmailExpiry < new Date()) {
    res.status(400).send(confirmHtml("error", "This confirmation link has expired. Please request a new verification email."));
    return;
  }
  await db.update(assetsTable)
    .set({ verificationStatus: "verified", verificationEmailToken: null, verificationEmailExpiry: null })
    .where(eq(assetsTable.id, assetId));
  // Sync: always propagate to all matching assets across all tenants (bidirectional)
  const syncedCount = await syncDomainVerification(assetId, asset.value);
  res.send(confirmHtml("success", `Asset <strong>${asset.name}</strong> (${asset.value}) has been successfully verified.${syncedCount > 0 ? ` ${syncedCount} matching asset(s) in other tenants also verified.` : ""}`));
});

function confirmHtml(type: "success" | "error", message: string): string {
  const color = type === "success" ? "#22c55e" : "#ef4444";
  const icon = type === "success" ? "✓" : "✗";
  const title = type === "success" ? "Ownership Verified" : "Verification Failed";
  return `<!DOCTYPE html><html><head><meta charset="utf-8"><style>
    body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0a0a0a;color:#e5e5e5;margin:0;display:flex;align-items:center;justify-content:center;min-height:100vh;}
    .card{background:#111;border:1px solid #222;border-radius:12px;padding:48px;max-width:440px;text-align:center;}
    .icon{font-size:48px;color:${color};margin-bottom:20px;}
    h1{font-size:22px;font-weight:700;color:#fff;margin:0 0 12px;}
    p{font-size:14px;color:#999;line-height:1.6;margin:0 0 24px;}
    a{display:inline-block;background:#7c3aed;color:#fff;text-decoration:none;padding:12px 24px;border-radius:8px;font-weight:600;font-size:14px;}
  </style></head><body><div class="card">
    <div class="icon">${icon}</div>
    <h1>${title}</h1>
    <p>${message}</p>
    <a href="/">Go to Sentinelware &rarr;</a>
  </div></body></html>`;
}

// Initiate asset ownership verification (generate token + send email/instructions)
router.post("/assets/:assetId/verify", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const params = VerifyAssetParams.safeParse(req.params);
  if (!params.success) { res.status(400).json({ error: params.error.message }); return; }
  const body = VerifyAssetBody.safeParse(req.body);
  if (!body.success) { res.status(400).json({ error: body.error.message }); return; }

  const amTidsV = req.user!.role === "account_manager" ? await getAmClientTenantIds(req.user!.userId) : undefined;
  const [existing] = await db.select().from(assetsTable)
    .where(assetAccessFilter(params.data.assetId, req.user!, amTidsV));
  if (!existing) { res.status(404).json({ error: "Asset not found" }); return; }

  const method = (body.data as any).method ?? "dns_txt";

  // Generate/reuse main verification token
  let token = existing.verificationToken;
  if (!token || !token.startsWith("sentinelware-")) {
    token = `sentinelware-${crypto.randomBytes(16).toString("hex")}`;
  }

  const domain = existing.value.replace(/^https?:\/\//, "").split("/")[0].split(":")[0];

  if (method === "email") {
    const emailToken = crypto.randomBytes(32).toString("hex");
    const expiry = new Date(Date.now() + 60 * 60 * 1000); // 1 hour
    const baseUrl = getPlatformBaseUrl(req as any);
    const confirmUrl = `${baseUrl}/api/assets/${existing.id}/verify/email-confirm?token=${emailToken}`;
    const rawEmailUsername = (body.data as any).emailUsername ?? req.body.emailUsername;
    const emailUsername = typeof rawEmailUsername === "string" && rawEmailUsername.trim()
      ? rawEmailUsername.trim()
      : "admin";
    const adminEmail = `${emailUsername}@${domain}`;

    await db.update(assetsTable)
      .set({ verificationToken: token, verificationMethod: method, verificationStatus: "pending",
             verificationEmailToken: emailToken, verificationEmailExpiry: expiry })
      .where(eq(assetsTable.id, params.data.assetId));

    await sendEmail({
      to: adminEmail,
      subject: `Verify ownership of ${domain} — Sentinelware`,
      html: verificationEmailHtml({ assetName: existing.name, domain, token: emailToken, confirmUrl }),
    });

    res.json({
      method,
      challenge: token,
      instructions: `A verification email has been sent to ${adminEmail}. Click the link in the email to confirm ownership.`,
      emailSentTo: adminEmail,
      expiresIn: "1 hour",
    });
    return;
  }

  // dns_txt / http_file / cloud — generate token, store method
  await db.update(assetsTable)
    .set({ verificationToken: token, verificationMethod: method, verificationStatus: "pending" })
    .where(eq(assetsTable.id, params.data.assetId));

  if (method === "http_file") {
    res.json({
      method,
      challenge: token,
      instructions: `Create a file at /.well-known/sentinelware-verification.txt on your web server with exactly this content: ${token}`,
      fileContent: token,
      filePath: "/.well-known/sentinelware-verification.txt",
      checkUrl: `https://${domain}/.well-known/sentinelware-verification.txt`,
    });
    return;
  }

  if (method === "cloud") {
    res.json({
      method,
      challenge: token,
      instructions: `Add the following tag/label to your cloud resource to prove ownership.`,
      tagKey: "sentinelware-verify",
      tagValue: token,
      cloudInstructions: {
        aws: `aws resourcegroupstaggingapi tag-resources --resource-arn-list <your-resource-arn> --tags sentinelware-verify=${token}`,
        gcp: `gcloud compute instances add-labels <instance> --labels=sentinelware-verify=${token}`,
        azure: `az resource tag --ids <resource-id> --tags sentinelware-verify=${token}`,
      },
    });
    return;
  }

  // dns_txt (default)
  res.json({
    method: "dns_txt",
    challenge: token,
    instructions: `Add a DNS TXT record to your domain with value: ${token}`,
    txtRecord: { type: "TXT", host: "sentinelwares", value: token, ttl: 300 },
  });
});

// Check verification status by method
router.post("/assets/:assetId/verify/check", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const params = CheckAssetVerificationParams.safeParse(req.params);
  if (!params.success) { res.status(400).json({ error: params.error.message }); return; }

  const amTidsC = req.user!.role === "account_manager" ? await getAmClientTenantIds(req.user!.userId) : undefined;
  const [asset] = await db.select().from(assetsTable)
    .where(assetAccessFilter(params.data.assetId, req.user!, amTidsC));
  if (!asset) { res.status(404).json({ error: "Asset not found" }); return; }

  // Already verified (e.g. email confirm link clicked before this poll)
  if (asset.verificationStatus === "verified") {
    res.json({ verified: true, message: "Asset ownership is verified." });
    return;
  }

  const token = asset.verificationToken;
  if (!token) {
    res.status(400).json({ error: "No verification in progress. Start verification first." });
    return;
  }

  const method = asset.verificationMethod ?? "dns_txt";
  const domain = asset.value.replace(/^https?:\/\//, "").split("/")[0].split(":")[0];

  // ── Email: check if the confirm link was clicked (token cleared = verified) ──
  if (method === "email") {
    if (asset.verificationEmailToken === null) {
      // Already handled by email-confirm endpoint — status should already be verified
      res.json({ verified: true, message: "Email confirmed. Asset ownership verified." });
    } else {
      res.json({ verified: false, message: "Email confirmation pending. Check your inbox and click the verification link." });
    }
    return;
  }

  // ── HTTP File: real fetch ─────────────────────────────────────────────────
  if (method === "http_file") {
    const fileUrl = `https://${domain}/.well-known/sentinelware-verification.txt`;
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 8000);
      const resp = await fetch(fileUrl, { signal: controller.signal });
      clearTimeout(timeout);
      if (!resp.ok) {
        res.json({ verified: false, message: `Could not fetch ${fileUrl} (HTTP ${resp.status}). Make sure the file is accessible.` });
        return;
      }
      const text = (await resp.text()).trim();
      if (text === token) {
        await db.update(assetsTable)
          .set({ verificationStatus: "verified" })
          .where(eq(assetsTable.id, params.data.assetId));
        await logAudit(req.user!, "verify_asset", "asset", params.data.assetId);
        const synced = await syncDomainVerification(params.data.assetId, asset.value);
        res.json({ verified: true, message: `File found at ${fileUrl}. Asset ownership verified.${synced > 0 ? ` ${synced} matching asset(s) in other tenants also verified.` : ""}` });
      } else {
        res.json({ verified: false, message: `File found but content does not match. Expected: ${token}` });
      }
    } catch (err: any) {
      const msg = err?.name === "AbortError"
        ? `Request to ${fileUrl} timed out. Ensure the file is publicly accessible.`
        : `Could not reach ${fileUrl}. Make sure the file is deployed and publicly accessible.`;
      res.json({ verified: false, message: msg });
    }
    return;
  }

  // ── Cloud: DNS fallback or admin manual verification ──────────────────────
  if (method === "cloud") {
    // Try DNS first (some cloud providers expose domain ownership via DNS)
    if (asset.type === "domain" || asset.type === "subdomain" || asset.type === "url") {
      try {
        const records = await dns.resolveTxt(`sentinelwares.${domain}`);
        const flat = records.flat();
        if (flat.some(r => r === token)) {
          await db.update(assetsTable)
            .set({ verificationStatus: "verified" })
            .where(eq(assetsTable.id, params.data.assetId));
          await logAudit(req.user!, "verify_asset", "asset", params.data.assetId);
          const synced = await syncDomainVerification(params.data.assetId, asset.value);
          res.json({ verified: true, message: `DNS TXT record found. Cloud asset ownership verified.${synced > 0 ? ` ${synced} matching asset(s) in other tenants also verified.` : ""}` });
          return;
        }
      } catch { /* no DNS record — fall through */ }
    }
    // For cloud_asset type and non-domain: trust admin confirmation, or client claim
    if (req.user!.role === "client") {
      // Client claims they've added the tag — mark as pending (admin reviews)
      res.json({ verified: false, message: "Your cloud verification claim has been submitted. An administrator will review and confirm ownership." });
      return;
    }
    // Admin/AM can manually confirm
    await db.update(assetsTable)
      .set({ verificationStatus: "verified" })
      .where(eq(assetsTable.id, params.data.assetId));
    await logAudit(req.user!, "verify_asset", "asset", params.data.assetId);
    const syncedCloud = await syncDomainVerification(params.data.assetId, asset.value);
    res.json({ verified: true, message: `Cloud asset ownership confirmed by administrator.${syncedCloud > 0 ? ` ${syncedCloud} matching asset(s) in other tenants also verified.` : ""}` });
    return;
  }

  // ── DNS TXT (default) ─────────────────────────────────────────────────────
  if (asset.type === "domain" || asset.type === "subdomain" || asset.type === "url") {
    try {
      const records = await dns.resolveTxt(`sentinelwares.${domain}`);
      const flat = records.flat();
      if (flat.some(r => r === token)) {
        await db.update(assetsTable)
          .set({ verificationStatus: "verified" })
          .where(eq(assetsTable.id, params.data.assetId));
        await logAudit(req.user!, "verify_asset", "asset", params.data.assetId);
        const synced = await syncDomainVerification(params.data.assetId, asset.value);
        res.json({ verified: true, message: `DNS TXT record found. Asset ownership verified.${synced > 0 ? ` ${synced} matching asset(s) in other tenants also verified.` : ""}` });
      } else {
        res.json({ verified: false, message: `TXT record not found yet. Expected value: ${token} at sentinelwares.${domain}` });
      }
      return;
    } catch {
      res.json({ verified: false, message: `Could not resolve sentinelwares.${domain}. Make sure the TXT record is added and DNS has propagated (up to 24h).` });
      return;
    }
  }

  // Non-domain, non-specific-method: admin/AM manual confirm, client blocked
  if (req.user!.role === "client") {
    res.status(403).json({ error: "Only domain/URL assets can be self-verified. Contact your account manager." });
    return;
  }
  await db.update(assetsTable)
    .set({ verificationStatus: "verified" })
    .where(eq(assetsTable.id, params.data.assetId));
  await logAudit(req.user!, "verify_asset", "asset", params.data.assetId);
  const syncedFallback = await syncDomainVerification(params.data.assetId, asset.value);
  res.json({ verified: true, message: `Asset ownership successfully verified.${syncedFallback > 0 ? ` ${syncedFallback} matching asset(s) in other tenants also verified.` : ""}` });
});

// ── Manual Verification (admin / super_admin only) ────────────────────────
router.post("/assets/:assetId/verify/manual", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const role = req.user!.role;
  if (role !== "admin" && role !== "super_admin" && role !== "manager") {
    res.status(403).json({ error: "Only administrators can manually verify assets." });
    return;
  }
  const assetId = parseInt(req.params.assetId, 10);
  if (isNaN(assetId)) { res.status(400).json({ error: "Invalid asset ID" }); return; }

  const [asset] = await db.select().from(assetsTable)
    .where(assetAccessFilter(assetId, req.user!));
  if (!asset) { res.status(404).json({ error: "Asset not found" }); return; }

  const isAdminRoleManual = role === "super_admin" || role === "admin";

  if (asset.verificationStatus === "verified") {
    // Asset itself is already verified — but still sync counterparts in case they aren't
    const syncedAlready = isAdminRoleManual ? await syncDomainVerification(assetId, asset.value) : 0;
    res.json({
      verified: true,
      message: `Asset is already verified.${syncedAlready > 0 ? ` ${syncedAlready} matching asset(s) in other tenants also verified.` : ""}`,
      syncedTenantAssets: syncedAlready,
    });
    return;
  }

  await db.update(assetsTable)
    .set({ verificationStatus: "verified", verificationToken: null })
    .where(eq(assetsTable.id, assetId));

  await logAudit(req.user!, "manual_verify_asset", "asset", assetId);
  const syncedManual = isAdminRoleManual ? await syncDomainVerification(assetId, asset.value) : 0;
  res.json({
    verified: true,
    message: `Asset ownership manually verified by administrator.${syncedManual > 0 ? ` ${syncedManual} matching asset(s) in other tenants also verified.` : ""}`,
    syncedTenantAssets: syncedManual,
  });
});

// ── Technology Detection ─────────────────────────────────────────────────

// List stored technology detections for an asset
router.get("/assets/:assetId/technologies", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const assetId = parseInt(req.params.assetId, 10);
  if (isNaN(assetId)) { res.status(400).json({ error: "Invalid assetId" }); return; }

  const rows = await db.select().from(technologyDetectionsTable)
    .where(and(
      eq(technologyDetectionsTable.assetId, assetId),
      eq(technologyDetectionsTable.tenantId, req.user!.tenantId),
    ))
    .orderBy(desc(technologyDetectionsTable.detectedAt));

  res.json(rows.map(r => ({
    id: r.id, assetId: r.assetId, scanId: r.scanId,
    technology: r.technology, slug: r.slug, category: r.category,
    version: r.version, confidence: r.confidence,
    website: r.website, cpe: r.cpe, icon: r.icon,
    detectedAt: r.detectedAt.toISOString(),
  })));
});

// Run real HTTP technology fingerprinting and store results
router.post("/assets/:assetId/tech-scan", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const assetId = parseInt(req.params.assetId, 10);
  if (isNaN(assetId)) { res.status(400).json({ error: "Invalid assetId" }); return; }

  const [asset] = await db.select().from(assetsTable)
    .where(and(eq(assetsTable.id, assetId), eq(assetsTable.tenantId, req.user!.tenantId)));
  if (!asset) { res.status(404).json({ error: "Asset not found" }); return; }

  // Only web-addressable assets can be fingerprinted
  const webTypes = ["domain", "subdomain", "url", "ip"];
  if (!webTypes.includes(asset.type)) {
    res.status(422).json({ error: `Tech scanning is only supported for domain, subdomain, url, and ip assets (got: ${asset.type})` });
    return;
  }

  const targetUrl = asset.value;
  const techs = await detectTechnologies(targetUrl);

  const scannedAt = new Date();

  // Remove any previous detections for this asset, then insert fresh results
  await db.delete(technologyDetectionsTable)
    .where(and(
      eq(technologyDetectionsTable.assetId, assetId),
      eq(technologyDetectionsTable.tenantId, req.user!.tenantId),
    ));

  let inserted: (typeof technologyDetectionsTable.$inferSelect)[] = [];
  if (techs.length > 0) {
    inserted = await db.insert(technologyDetectionsTable).values(
      techs.map(t => ({
        tenantId: req.user!.tenantId,
        assetId,
        technology: t.name,
        slug: t.slug,
        category: t.category,
        version: t.version ?? null,
        confidence: t.confidence,
        website: t.website ?? null,
        cpe: t.cpe ?? null,
        icon: t.icon ?? null,
        detectedAt: scannedAt,
      }))
    ).returning();
  }

  await logAudit(req.user!, "tech_scan", "asset", assetId);

  res.json({
    technologies: inserted.map(r => ({
      id: r.id, assetId: r.assetId, scanId: r.scanId,
      technology: r.technology, slug: r.slug, category: r.category,
      version: r.version, confidence: r.confidence,
      website: r.website, cpe: r.cpe, icon: r.icon,
      detectedAt: r.detectedAt.toISOString(),
    })),
    scannedAt: scannedAt.toISOString(),
  });
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
