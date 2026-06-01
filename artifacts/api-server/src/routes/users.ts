import { Router } from "express";
import { eq, and } from "drizzle-orm";
import { db, usersTable } from "@workspace/db";
import { CreateUserBody, GetUserParams, UpdateUserParams, UpdateUserBody, DeleteUserParams } from "@workspace/api-zod";
import { requireAuth, hashPassword, type AuthenticatedRequest } from "../lib/auth";
import { logAudit } from "../lib/audit";

const router = Router();

function toUserResponse(u: typeof usersTable.$inferSelect) {
  return {
    id: u.id, email: u.email, firstName: u.firstName, lastName: u.lastName,
    role: u.role, tenantId: u.tenantId, isActive: u.isActive,
    lastLoginAt: u.lastLoginAt?.toISOString() ?? null,
    createdAt: u.createdAt.toISOString(),
  };
}

router.get("/users", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const users = await db.select().from(usersTable)
    .where(eq(usersTable.tenantId, req.user!.tenantId));
  res.json(users.map(toUserResponse));
});

router.post("/users", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const parsed = CreateUserBody.safeParse(req.body);
  if (!parsed.success) { res.status(400).json({ error: parsed.error.message }); return; }
  const passwordHash = await hashPassword(parsed.data.password);
  const [user] = await db.insert(usersTable).values({
    ...parsed.data, tenantId: req.user!.tenantId, passwordHash,
  }).returning();
  await logAudit(req.user!, "create_user", "user", user.id);
  res.status(201).json(toUserResponse(user));
});

router.get("/users/:userId", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const params = GetUserParams.safeParse(req.params);
  if (!params.success) { res.status(400).json({ error: params.error.message }); return; }
  const [user] = await db.select().from(usersTable)
    .where(and(eq(usersTable.id, params.data.userId), eq(usersTable.tenantId, req.user!.tenantId)));
  if (!user) { res.status(404).json({ error: "User not found" }); return; }
  res.json(toUserResponse(user));
});

router.patch("/users/:userId", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const params = UpdateUserParams.safeParse(req.params);
  if (!params.success) { res.status(400).json({ error: params.error.message }); return; }
  const parsed = UpdateUserBody.safeParse(req.body);
  if (!parsed.success) { res.status(400).json({ error: parsed.error.message }); return; }
  const [user] = await db.update(usersTable).set(parsed.data)
    .where(and(eq(usersTable.id, params.data.userId), eq(usersTable.tenantId, req.user!.tenantId)))
    .returning();
  if (!user) { res.status(404).json({ error: "User not found" }); return; }
  await logAudit(req.user!, "update_user", "user", user.id);
  res.json(toUserResponse(user));
});

router.delete("/users/:userId", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const params = DeleteUserParams.safeParse(req.params);
  if (!params.success) { res.status(400).json({ error: params.error.message }); return; }
  const [user] = await db.delete(usersTable)
    .where(and(eq(usersTable.id, params.data.userId), eq(usersTable.tenantId, req.user!.tenantId)))
    .returning();
  if (!user) { res.status(404).json({ error: "User not found" }); return; }
  await logAudit(req.user!, "delete_user", "user", user.id);
  res.sendStatus(204);
});

export default router;
