import { Router } from "express";
import { eq, and, inArray } from "drizzle-orm";
import { db, usersTable, tenantsTable, accountManagerClientsTable } from "@workspace/db";
import { CreateUserBody, GetUserParams, UpdateUserParams, DeleteUserParams } from "@workspace/api-zod";
import { requireAuth, hashPassword, type AuthenticatedRequest } from "../lib/auth";
import { logAudit } from "../lib/audit";

const router = Router();

const ROLE_HIERARCHY: Record<string, string[]> = {
  super_admin: ["super_admin", "admin", "account_manager", "client"],
  admin: ["admin", "client"],
  account_manager: ["client"],
  client: [],
};

function toUserResponse(u: typeof usersTable.$inferSelect, tenantName?: string) {
  return {
    id: u.id, email: u.email, firstName: u.firstName, lastName: u.lastName,
    role: u.role, tenantId: u.tenantId, isActive: u.isActive,
    tenantName: tenantName ?? null,
    lastLoginAt: u.lastLoginAt?.toISOString() ?? null,
    createdAt: u.createdAt.toISOString(),
    twoFactorEnabled: u.twoFactorEnabled,
    avatarUrl: u.avatarUrl ?? null,
    isEmailVerified: u.isEmailVerified,
  };
}

router.get("/users", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const { role, tenantId, userId } = req.user!;

  if (role === "super_admin") {
    const users = await db.select().from(usersTable).orderBy(usersTable.createdAt);
    const tIds = [...new Set(users.map(u => u.tenantId))];
    const tenants = tIds.length > 0
      ? await db.select({ id: tenantsTable.id, name: tenantsTable.name }).from(tenantsTable)
          .where(inArray(tenantsTable.id, tIds))
      : [];
    const tMap = new Map(tenants.map(t => [t.id, t.name]));
    res.json(users.map(u => toUserResponse(u, tMap.get(u.tenantId))));
    return;
  }

  if (role === "account_manager") {
    const clients = await db.select({ clientId: accountManagerClientsTable.clientId })
      .from(accountManagerClientsTable)
      .where(eq(accountManagerClientsTable.managerId, userId));
    const clientIds = clients.map(c => c.clientId);
    if (clientIds.length === 0) { res.json([]); return; }
    const users = await db.select().from(usersTable).where(inArray(usersTable.id, clientIds));
    const tMap = new Map(await db.select({ id: tenantsTable.id, name: tenantsTable.name }).from(tenantsTable)
      .then(rows => rows.map(r => [r.id, r.name] as [number, string])));
    res.json(users.map(u => toUserResponse(u, tMap.get(u.tenantId))));
    return;
  }

  const users = await db.select().from(usersTable).where(eq(usersTable.tenantId, tenantId));
  res.json(users.map(u => toUserResponse(u)));
});

router.post("/users", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const { role, tenantId, userId } = req.user!;
  const parsed = CreateUserBody.safeParse(req.body);
  if (!parsed.success) { res.status(400).json({ error: parsed.error.message }); return; }

  const newRole = parsed.data.role ?? "client";
  const allowedRoles = ROLE_HIERARCHY[role] ?? [];
  if (!allowedRoles.includes(newRole)) {
    res.status(403).json({ error: `Your role cannot create users with role: ${newRole}` }); return;
  }

  const targetTenantId = (role === "super_admin" || role === "account_manager") && (req.body as any).tenantId
    ? Number((req.body as any).tenantId)
    : tenantId;

  const passwordHash = await hashPassword(parsed.data.password);
  const [user] = await db.insert(usersTable).values({
    ...parsed.data, tenantId: targetTenantId, passwordHash,
  }).returning();
  await logAudit(req.user! as any, "create_user", "user", user.id);
  res.status(201).json(toUserResponse(user));
});

router.get("/users/:userId", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const params = GetUserParams.safeParse(req.params);
  if (!params.success) { res.status(400).json({ error: params.error.message }); return; }
  const { role, tenantId } = req.user!;

  if (role === "super_admin") {
    const [user] = await db.select().from(usersTable).where(eq(usersTable.id, params.data.userId));
    if (!user) { res.status(404).json({ error: "User not found" }); return; }
    const [tenant] = await db.select({ name: tenantsTable.name }).from(tenantsTable).where(eq(tenantsTable.id, user.tenantId));
    res.json(toUserResponse(user, tenant?.name));
    return;
  }

  const [user] = await db.select().from(usersTable)
    .where(and(eq(usersTable.id, params.data.userId), eq(usersTable.tenantId, tenantId)));
  if (!user) { res.status(404).json({ error: "User not found" }); return; }
  res.json(toUserResponse(user));
});

router.patch("/users/:userId", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const params = UpdateUserParams.safeParse(req.params);
  if (!params.success) { res.status(400).json({ error: params.error.message }); return; }
  const { role, tenantId } = req.user!;

  const body = req.body as Record<string, unknown>;
  const updateData: Record<string, unknown> = {};

  // Fields any authorized user can update
  if (body.firstName !== undefined) updateData.firstName = String(body.firstName);
  if (body.lastName !== undefined) updateData.lastName = String(body.lastName);
  if (body.role !== undefined) {
    const allowedRoles = ROLE_HIERARCHY[role] ?? [];
    if (!allowedRoles.includes(body.role as string)) {
      res.status(403).json({ error: "You cannot assign this role" }); return;
    }
    updateData.role = body.role;
  }
  if (body.isActive !== undefined) updateData.isActive = Boolean(body.isActive);

  // Super admin only fields
  if (role === "super_admin") {
    if (body.email !== undefined && String(body.email).trim()) {
      updateData.email = String(body.email).trim().toLowerCase();
    }
    if (body.newPassword !== undefined && String(body.newPassword).length >= 8) {
      updateData.passwordHash = await hashPassword(String(body.newPassword));
    }
    if (body.tenantId !== undefined && body.tenantId !== "") {
      updateData.tenantId = Number(body.tenantId);
    }
    if (body.twoFactorEnabled === false) {
      updateData.twoFactorEnabled = false;
      updateData.twoFactorOtp = null;
      updateData.twoFactorOtpExpiresAt = null;
    }
  }

  if (Object.keys(updateData).length === 0) {
    res.status(400).json({ error: "No valid fields to update" }); return;
  }

  const whereClause = role === "super_admin"
    ? eq(usersTable.id, params.data.userId)
    : and(eq(usersTable.id, params.data.userId), eq(usersTable.tenantId, tenantId));

  const [user] = await db.update(usersTable).set(updateData).where(whereClause!).returning();
  if (!user) { res.status(404).json({ error: "User not found" }); return; }
  await logAudit(req.user! as any, "update_user", "user", user.id);

  const [tenant] = role === "super_admin"
    ? await db.select({ name: tenantsTable.name }).from(tenantsTable).where(eq(tenantsTable.id, user.tenantId))
    : [];
  res.json(toUserResponse(user, (tenant as any)?.name));
});

router.delete("/users/:userId", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const params = GetUserParams.safeParse(req.params);
  if (!params.success) { res.status(400).json({ error: params.error.message }); return; }
  const { role, tenantId } = req.user!;

  const whereClause = role === "super_admin"
    ? eq(usersTable.id, params.data.userId)
    : and(eq(usersTable.id, params.data.userId), eq(usersTable.tenantId, tenantId));

  const [user] = await db.delete(usersTable).where(whereClause!).returning();
  if (!user) { res.status(404).json({ error: "User not found" }); return; }
  await logAudit(req.user! as any, "delete_user", "user", user.id);
  res.sendStatus(204);
});

export default router;
