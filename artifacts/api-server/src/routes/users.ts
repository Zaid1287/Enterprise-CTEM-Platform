import { Router } from "express";
import { eq, and, inArray } from "drizzle-orm";
import { db, usersTable, tenantsTable, accountManagerClientsTable } from "@workspace/db";
import { CreateUserBody, GetUserParams, UpdateUserParams, UpdateUserBody, DeleteUserParams } from "@workspace/api-zod";
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
    const assignments = await db.select().from(accountManagerClientsTable)
      .where(eq(accountManagerClientsTable.accountManagerUserId, userId));
    const clientTenantIds = assignments.map(a => a.clientTenantId);
    if (clientTenantIds.length === 0) { res.json([]); return; }
    const users = await db.select().from(usersTable).where(inArray(usersTable.tenantId, clientTenantIds));
    const tenants = await db.select({ id: tenantsTable.id, name: tenantsTable.name }).from(tenantsTable)
      .where(inArray(tenantsTable.id, clientTenantIds));
    const tMap = new Map(tenants.map(t => [t.id, t.name]));
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

  let targetTenantId = tenantId;

  if (newRole === "super_admin" || newRole === "account_manager") {
    const [platformTenant] = await db.select().from(tenantsTable).where(eq(tenantsTable.isPlatform, true));
    if (platformTenant) targetTenantId = platformTenant.id;
  } else if (role === "super_admin" && req.body.tenantId) {
    targetTenantId = Number(req.body.tenantId);
  } else if (role === "account_manager" && req.body.tenantId) {
    const assignments = await db.select().from(accountManagerClientsTable)
      .where(eq(accountManagerClientsTable.accountManagerUserId, userId));
    const allowed = assignments.some(a => a.clientTenantId === Number(req.body.tenantId));
    if (!allowed) { res.status(403).json({ error: "Cannot create users in unassigned tenant" }); return; }
    targetTenantId = Number(req.body.tenantId);
  }

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
    res.json(toUserResponse(user));
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
  const parsed = UpdateUserBody.safeParse(req.body);
  if (!parsed.success) { res.status(400).json({ error: parsed.error.message }); return; }
  const { role, tenantId } = req.user!;

  const whereClause = role === "super_admin"
    ? eq(usersTable.id, params.data.userId)
    : and(eq(usersTable.id, params.data.userId), eq(usersTable.tenantId, tenantId));

  const [user] = await db.update(usersTable).set(parsed.data).where(whereClause!).returning();
  if (!user) { res.status(404).json({ error: "User not found" }); return; }
  await logAudit(req.user! as any, "update_user", "user", user.id);
  res.json(toUserResponse(user));
});

router.delete("/users/:userId", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const params = DeleteUserParams.safeParse(req.params);
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
