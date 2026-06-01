import { Router } from "express";
import { eq, and, ilike } from "drizzle-orm";
import { db, findingsTable, findingCommentsTable, assetsTable, usersTable } from "@workspace/db";
import {
  GetFindingParams, UpdateFindingParams, UpdateFindingBody,
  ListFindingsQueryParams, ListFindingCommentsParams,
  CreateFindingCommentParams, CreateFindingCommentBody,
} from "@workspace/api-zod";
import { requireAuth, type AuthenticatedRequest } from "../lib/auth";
import { logAudit } from "../lib/audit";

const router = Router();

function toFindingResponse(f: typeof findingsTable.$inferSelect, assetName?: string | null) {
  return {
    id: f.id, tenantId: f.tenantId, assetId: f.assetId, assetName: assetName ?? null,
    title: f.title, description: f.description, severity: f.severity, status: f.status,
    cve: f.cve, cvss: f.cvss, epss: f.epss, cwe: f.cwe, isKev: f.isKev,
    remediation: f.remediation, evidence: f.evidence, riskScore: f.riskScore,
    createdAt: f.createdAt.toISOString(), updatedAt: f.updatedAt.toISOString(),
  };
}

router.get("/findings", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const q = ListFindingsQueryParams.safeParse(req.query);
  const filters = [eq(findingsTable.tenantId, req.user!.tenantId)];
  if (q.success) {
    if (q.data.status) filters.push(eq(findingsTable.status, q.data.status));
    if (q.data.severity) filters.push(eq(findingsTable.severity, q.data.severity));
    if (q.data.assetId) filters.push(eq(findingsTable.assetId, q.data.assetId));
    if (q.data.search) filters.push(ilike(findingsTable.title, `%${q.data.search}%`));
  }
  const findings = await db.select({
    finding: findingsTable,
    assetName: assetsTable.name,
  }).from(findingsTable)
    .leftJoin(assetsTable, eq(findingsTable.assetId, assetsTable.id))
    .where(and(...filters));
  res.json(findings.map(({ finding, assetName }) => toFindingResponse(finding, assetName)));
});

router.get("/findings/:findingId", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const params = GetFindingParams.safeParse(req.params);
  if (!params.success) { res.status(400).json({ error: params.error.message }); return; }
  const [row] = await db.select({
    finding: findingsTable,
    assetName: assetsTable.name,
  }).from(findingsTable)
    .leftJoin(assetsTable, eq(findingsTable.assetId, assetsTable.id))
    .where(and(eq(findingsTable.id, params.data.findingId), eq(findingsTable.tenantId, req.user!.tenantId)));
  if (!row) { res.status(404).json({ error: "Finding not found" }); return; }
  res.json(toFindingResponse(row.finding, row.assetName));
});

router.patch("/findings/:findingId", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const params = UpdateFindingParams.safeParse(req.params);
  if (!params.success) { res.status(400).json({ error: params.error.message }); return; }
  const parsed = UpdateFindingBody.safeParse(req.body);
  if (!parsed.success) { res.status(400).json({ error: parsed.error.message }); return; }
  const [finding] = await db.update(findingsTable).set(parsed.data)
    .where(and(eq(findingsTable.id, params.data.findingId), eq(findingsTable.tenantId, req.user!.tenantId)))
    .returning();
  if (!finding) { res.status(404).json({ error: "Finding not found" }); return; }
  await logAudit(req.user!, "update_finding", "finding", finding.id, `status: ${parsed.data.status ?? "unchanged"}`);
  res.json(toFindingResponse(finding));
});

router.get("/findings/:findingId/comments", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const params = ListFindingCommentsParams.safeParse(req.params);
  if (!params.success) { res.status(400).json({ error: params.error.message }); return; }
  const comments = await db.select({
    comment: findingCommentsTable,
    authorName: usersTable.firstName,
    authorLast: usersTable.lastName,
  }).from(findingCommentsTable)
    .leftJoin(usersTable, eq(findingCommentsTable.userId, usersTable.id))
    .where(eq(findingCommentsTable.findingId, params.data.findingId));
  res.json(comments.map(({ comment, authorName, authorLast }) => ({
    id: comment.id, findingId: comment.findingId, userId: comment.userId,
    authorName: authorName ? `${authorName} ${authorLast ?? ""}`.trim() : "Unknown",
    content: comment.content, createdAt: comment.createdAt.toISOString(),
  })));
});

router.post("/findings/:findingId/comments", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const params = CreateFindingCommentParams.safeParse(req.params);
  if (!params.success) { res.status(400).json({ error: params.error.message }); return; }
  const parsed = CreateFindingCommentBody.safeParse(req.body);
  if (!parsed.success) { res.status(400).json({ error: parsed.error.message }); return; }
  const [comment] = await db.insert(findingCommentsTable).values({
    findingId: params.data.findingId, userId: req.user!.userId, content: parsed.data.content,
  }).returning();
  const [user] = await db.select().from(usersTable).where(eq(usersTable.id, req.user!.userId));
  res.status(201).json({
    id: comment.id, findingId: comment.findingId, userId: comment.userId,
    authorName: user ? `${user.firstName} ${user.lastName}` : "Unknown",
    content: comment.content, createdAt: comment.createdAt.toISOString(),
  });
});

export default router;
