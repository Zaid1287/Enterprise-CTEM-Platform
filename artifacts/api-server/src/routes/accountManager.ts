import { Router } from "express";
import { eq, inArray, and } from "drizzle-orm";
import { db, accountManagerClientsTable, tenantsTable, assetsTable, findingsTable, scansTable, usersTable } from "@workspace/db";
import { requireAuth, type AuthenticatedRequest } from "../lib/auth";

const router = Router();

router.get("/account-manager/clients", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const { role, userId } = req.user!;
  if (role !== "account_manager" && role !== "super_admin") {
    res.status(403).json({ error: "Forbidden" }); return;
  }

  const targetUserId = role === "super_admin" && req.query.userId
    ? Number(req.query.userId)
    : userId;

  const assignments = await db.select().from(accountManagerClientsTable)
    .where(eq(accountManagerClientsTable.accountManagerUserId, targetUserId));

  if (assignments.length === 0) { res.json([]); return; }

  const clientTenantIds = assignments.map(a => a.clientTenantId);
  const [clients, allAssets, allFindings, allScans] = await Promise.all([
    db.select().from(tenantsTable).where(inArray(tenantsTable.id, clientTenantIds)),
    db.select().from(assetsTable).where(inArray(assetsTable.tenantId, clientTenantIds)),
    db.select().from(findingsTable).where(inArray(findingsTable.tenantId, clientTenantIds)),
    db.select().from(scansTable).where(inArray(scansTable.tenantId, clientTenantIds)),
  ]);

  const result = clients.map(t => ({
    tenantId: t.id,
    tenantName: t.name,
    plan: t.plan,
    isActive: t.isActive,
    assetCount: allAssets.filter(a => a.tenantId === t.id).length,
    findingCount: allFindings.filter(f => f.tenantId === t.id).length,
    criticalCount: allFindings.filter(f => f.tenantId === t.id && f.severity === "critical").length,
    openFindingCount: allFindings.filter(f => f.tenantId === t.id && f.status === "open").length,
    activeScans: allScans.filter(s => s.tenantId === t.id && (s.status === "running" || s.status === "pending")).length,
    assignedAt: assignments.find(a => a.clientTenantId === t.id)?.assignedAt?.toISOString() ?? null,
    createdAt: t.createdAt.toISOString(),
  }));

  res.json(result);
});

router.post("/account-manager/clients", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const { role, userId } = req.user!;
  if (role !== "account_manager" && role !== "super_admin") {
    res.status(403).json({ error: "Forbidden" }); return;
  }
  const { clientTenantId, accountManagerUserId } = req.body;
  const amUserId = (role === "super_admin" && accountManagerUserId) ? Number(accountManagerUserId) : userId;
  if (!clientTenantId) { res.status(400).json({ error: "clientTenantId is required" }); return; }

  const existing = await db.select().from(accountManagerClientsTable)
    .where(and(
      eq(accountManagerClientsTable.accountManagerUserId, amUserId),
      eq(accountManagerClientsTable.clientTenantId, Number(clientTenantId))
    ));
  if (existing.length > 0) { res.status(409).json({ error: "Already assigned" }); return; }

  const [assignment] = await db.insert(accountManagerClientsTable).values({
    accountManagerUserId: amUserId,
    clientTenantId: Number(clientTenantId),
  }).returning();
  res.status(201).json(assignment);
});

router.delete("/account-manager/clients/:clientTenantId", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const { role, userId } = req.user!;
  if (role !== "account_manager" && role !== "super_admin") {
    res.status(403).json({ error: "Forbidden" }); return;
  }
  const clientTenantId = Number(req.params.clientTenantId);
  const amUserId = role === "super_admin" && req.query.amUserId
    ? Number(req.query.amUserId)
    : userId;
  await db.delete(accountManagerClientsTable)
    .where(and(
      eq(accountManagerClientsTable.accountManagerUserId, amUserId),
      eq(accountManagerClientsTable.clientTenantId, clientTenantId)
    ));
  res.sendStatus(204);
});

export default router;
