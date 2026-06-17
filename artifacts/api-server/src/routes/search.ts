/**
 * Full-text search — PostgreSQL tsvector / tsquery (OpenSearch equivalent).
 *
 * Searches assets, findings, and scans in parallel and returns ranked results.
 */
import { Router } from "express";
import { sql, and, eq } from "drizzle-orm";
import { db, assetsTable, findingsTable, scansTable } from "@workspace/db";
import { requireAuth, type AuthenticatedRequest } from "../lib/auth";
import { cacheGet, cacheSet, ck } from "../lib/cache";

const router = Router();

router.get("/search", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const q = (req.query.q as string ?? "").trim();
  const limit = Math.min(Number(req.query.limit ?? 20), 50);
  const tid = req.user!.tenantId;

  if (!q || q.length < 2) {
    res.json({ assets: [], findings: [], scans: [], total: 0 });
    return;
  }

  const cacheKey = ck("search", tid, encodeURIComponent(q), limit);
  const cached = await cacheGet<Record<string, unknown>>(cacheKey);
  if (cached) {
    res.json(cached);
    return;
  }

  const tsQuery = q
    .split(/\s+/)
    .filter(Boolean)
    .map((w) => `${w.replace(/[^a-zA-Z0-9]/g, "")}:*`)
    .join(" & ");

  if (!tsQuery) {
    res.json({ assets: [], findings: [], scans: [], total: 0 });
    return;
  }

  const [assetRows, findingRows, scanRows] = await Promise.all([
    db
      .select({
        id:          assetsTable.id,
        name:        assetsTable.name,
        type:        assetsTable.type,
        value:       assetsTable.value,
        riskLevel:   assetsTable.riskLevel,
        tags:        assetsTable.tags,
        rank:        sql<number>`ts_rank(
          to_tsvector('english',
            coalesce(${assetsTable.name},'') || ' ' ||
            coalesce(${assetsTable.value},'') || ' ' ||
            coalesce(${assetsTable.type},'') || ' ' ||
            coalesce(${assetsTable.description},'')
          ),
          to_tsquery('english', ${tsQuery})
        )`,
      })
      .from(assetsTable)
      .where(
        and(
          eq(assetsTable.tenantId, tid),
          sql`to_tsvector('english',
            coalesce(${assetsTable.name},'') || ' ' ||
            coalesce(${assetsTable.value},'') || ' ' ||
            coalesce(${assetsTable.type},'') || ' ' ||
            coalesce(${assetsTable.description},'')
          ) @@ to_tsquery('english', ${tsQuery})`,
        ),
      )
      .orderBy(sql`rank desc`)
      .limit(limit),

    db
      .select({
        id:          findingsTable.id,
        title:       findingsTable.title,
        severity:    findingsTable.severity,
        status:      findingsTable.status,
        cve:         findingsTable.cve,
        cvss:        findingsTable.cvss,
        assetId:     findingsTable.assetId,
        rank:        sql<number>`ts_rank(
          to_tsvector('english',
            coalesce(${findingsTable.title},'') || ' ' ||
            coalesce(${findingsTable.description},'') || ' ' ||
            coalesce(${findingsTable.cve},'') || ' ' ||
            coalesce(${findingsTable.cwe},'')
          ),
          to_tsquery('english', ${tsQuery})
        )`,
      })
      .from(findingsTable)
      .where(
        and(
          eq(findingsTable.tenantId, tid),
          sql`to_tsvector('english',
            coalesce(${findingsTable.title},'') || ' ' ||
            coalesce(${findingsTable.description},'') || ' ' ||
            coalesce(${findingsTable.cve},'') || ' ' ||
            coalesce(${findingsTable.cwe},'')
          ) @@ to_tsquery('english', ${tsQuery})`,
        ),
      )
      .orderBy(sql`rank desc`)
      .limit(limit),

    db
      .select({
        id:     scansTable.id,
        name:   scansTable.name,
        type:   scansTable.type,
        status: scansTable.status,
        createdAt: scansTable.createdAt,
        rank:   sql<number>`ts_rank(
          to_tsvector('english', coalesce(${scansTable.name},'') || ' ' || coalesce(${scansTable.type},'')),
          to_tsquery('english', ${tsQuery})
        )`,
      })
      .from(scansTable)
      .where(
        and(
          eq(scansTable.tenantId, tid),
          sql`to_tsvector('english', coalesce(${scansTable.name},'') || ' ' || coalesce(${scansTable.type},''))
              @@ to_tsquery('english', ${tsQuery})`,
        ),
      )
      .orderBy(sql`rank desc`)
      .limit(limit),
  ]);

  const result = {
    assets:   assetRows.map((r) => ({ ...r, _type: "asset"   as const })),
    findings: findingRows.map((r) => ({ ...r, _type: "finding" as const })),
    scans:    scanRows.map((r) => ({
      ...r,
      createdAt: r.createdAt.toISOString(),
      _type: "scan" as const,
    })),
    total: assetRows.length + findingRows.length + scanRows.length,
    query: q,
  };

  await cacheSet(cacheKey, result, 60);
  res.json(result);
});

export default router;
