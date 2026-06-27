import { Router } from "express";
import { eq, and, inArray } from "drizzle-orm";
import { db, invitationsTable, assetsTable, tenantsTable } from "@workspace/db";
import { requireAuth, type AuthenticatedRequest } from "../lib/auth";
import { sendEmail } from "../lib/email";
import crypto from "crypto";

const EXTERNAL_ROLES = ["vendor", "employee", "third_party"];
const ALL_ALLOWED_ROLES = ["vendor", "employee", "third_party", "admin", "account_manager", "client"];

function getPlatformBaseUrl(req: { get: (h: string) => string | undefined }): string {
  const domains = process.env.REPLIT_DOMAINS;
  if (domains) return `https://${domains.split(",")[0].trim()}`;
  return `http://${req.get("host") ?? "localhost:80"}`;
}

const router = Router();

router.get("/invitations", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const invitations = await db.select()
    .from(invitationsTable)
    .where(eq(invitationsTable.tenantId, req.user!.tenantId));
  res.json(invitations);
});

router.post("/invitations", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const { name, email, role, assetIds } = req.body;
  if (!name || !email || !role) {
    res.status(400).json({ error: "name, email, and role are required" });
    return;
  }

  if (!ALL_ALLOWED_ROLES.includes(role)) {
    res.status(400).json({ error: `Role must be one of: ${ALL_ALLOWED_ROLES.join(", ")}` });
    return;
  }

  // External roles require at least one asset to be specified
  const isExternal = EXTERNAL_ROLES.includes(role);
  const parsedAssetIds: number[] = Array.isArray(assetIds) ? assetIds.map(Number).filter(n => !isNaN(n)) : [];
  if (isExternal && parsedAssetIds.length === 0) {
    res.status(400).json({ error: "At least one asset must be selected for vendor/employee/third_party roles" });
    return;
  }

  // Validate all assetIds belong to the inviting tenant
  if (parsedAssetIds.length > 0) {
    const assetRows = await db.select({ id: assetsTable.id })
      .from(assetsTable)
      .where(and(inArray(assetsTable.id, parsedAssetIds), eq(assetsTable.tenantId, req.user!.tenantId)));
    if (assetRows.length !== parsedAssetIds.length) {
      res.status(400).json({ error: "One or more asset IDs are invalid or do not belong to your tenant" });
      return;
    }
  }

  // Fetch asset names for the email
  let assetNames: string[] = [];
  if (parsedAssetIds.length > 0) {
    const assetRows = await db.select({ name: assetsTable.name }).from(assetsTable)
      .where(inArray(assetsTable.id, parsedAssetIds));
    assetNames = assetRows.map(a => a.name);
  }

  // Fetch tenant name for the email
  const [tenant] = await db.select({ name: tenantsTable.name }).from(tenantsTable)
    .where(eq(tenantsTable.id, req.user!.tenantId));

  const token = crypto.randomBytes(32).toString("hex");
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days

  const [invitation] = await db.insert(invitationsTable).values({
    tenantId: req.user!.tenantId,
    invitedByUserId: req.user!.userId,
    name,
    email,
    role,
    assetIds: parsedAssetIds,
    token,
    status: "pending",
    expiresAt,
  }).returning();

  const baseUrl = getPlatformBaseUrl(req as any);
  const acceptLink = `${baseUrl}/accept-invitation?token=${token}`;
  const tenantName = tenant?.name ?? "Sentinelware";

  await sendEmail({
    to: email,
    subject: `You've been invited to ${tenantName} on Sentinelware`,
    html: `<!DOCTYPE html>
<html>
<head>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0a0a0a; color: #e5e5e5; margin: 0; padding: 40px 20px; }
    .container { max-width: 480px; margin: 0 auto; background: #111; border: 1px solid #222; border-radius: 12px; padding: 40px; }
    .brand { font-size: 18px; font-weight: 700; color: #fff; margin-bottom: 32px; }
    h1 { font-size: 22px; font-weight: 700; margin: 0 0 8px; color: #fff; }
    p { font-size: 14px; color: #999; line-height: 1.6; margin: 0 0 16px; }
    .btn { display: inline-block; background: #7c3aed; color: #fff; text-decoration: none; padding: 12px 24px; border-radius: 8px; font-weight: 600; font-size: 14px; margin: 16px 0; }
    .asset-list { background: #0d0d0d; border: 1px solid #1e1e1e; border-radius: 8px; padding: 12px 16px; margin: 8px 0 16px; }
    .asset-list li { font-size: 13px; color: #bbb; margin: 4px 0; }
    .footer { font-size: 12px; color: #555; margin-top: 32px; padding-top: 24px; border-top: 1px solid #1e1e1e; }
  </style>
</head>
<body>
  <div class="container">
    <div class="brand">Sentinelware</div>
    <h1>You've been invited</h1>
    <p>Hi ${name},</p>
    <p>You have been invited to join <strong style="color:#e5e5e5;">${tenantName}</strong> on Sentinelware as a <strong style="color:#e5e5e5;">${role.replace(/_/g, " ")}</strong>.</p>
    ${assetNames.length > 0 ? `<p style="margin-bottom:4px;">You will have access to:</p>
    <ul class="asset-list">${assetNames.map(n => `<li>• ${n}</li>`).join("")}</ul>` : ""}
    <p>Click the button below to create your account and get started:</p>
    <a href="${acceptLink}" class="btn">Accept Invitation &rarr;</a>
    <p style="font-size:12px;color:#555;">Or copy this link into your browser:<br/><span style="color:#7c3aed;word-break:break-all;">${acceptLink}</span></p>
    <p>This invitation expires in 7 days.</p>
    <div class="footer">&copy; ${new Date().getFullYear()} Sentinelware. All rights reserved.</div>
  </div>
</body>
</html>`,
  });

  res.status(201).json(invitation);
});

router.patch("/invitations/:id", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const id = parseInt(req.params.id, 10);
  const { status } = req.body;

  if (!["pending", "accepted", "rejected"].includes(status)) {
    res.status(400).json({ error: "Invalid status" });
    return;
  }

  const [updated] = await db.update(invitationsTable)
    .set({ status, respondedAt: new Date() })
    .where(and(eq(invitationsTable.id, id), eq(invitationsTable.tenantId, req.user!.tenantId)))
    .returning();

  if (!updated) { res.status(404).json({ error: "Invitation not found" }); return; }
  res.json(updated);
});

router.delete("/invitations/:id", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const id = parseInt(req.params.id, 10);
  const [deleted] = await db.delete(invitationsTable)
    .where(and(eq(invitationsTable.id, id), eq(invitationsTable.tenantId, req.user!.tenantId)))
    .returning();
  if (!deleted) { res.status(404).json({ error: "Invitation not found" }); return; }
  res.sendStatus(204);
});

export default router;
