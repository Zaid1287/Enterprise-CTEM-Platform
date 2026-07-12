import { Router } from "express";
import { eq, and, inArray } from "drizzle-orm";
import { getAmClientTenantIds } from "../lib/amScoping";
import { getPrivilegedTenantIds, resolvePrivilegedTenantFilter } from "../lib/tenantScoping";
import { db, complianceFrameworksTable, complianceControlsTable, complianceControlAssetsTable, tenantsTable, assetGroupsTable, assetsTable } from "@workspace/db";
import {
  GetComplianceControlParams, UpdateComplianceControlParams,
  UpdateComplianceControlBody, ListComplianceControlsQueryParams,
} from "@workspace/api-zod";
import { requireAuth, requireRole, denyExternalMembers, type AuthenticatedRequest } from "../lib/auth";
import { logAudit } from "../lib/audit";
import { getPlatformTenantId } from "../lib/seedPlatform";
import multer from "multer";
import path from "path";
import fs from "fs";
import crypto from "crypto";

const router = Router();
router.use(denyExternalMembers);

const EVIDENCE_DIR = path.join(process.cwd(), "compliance-evidence");
if (!fs.existsSync(EVIDENCE_DIR)) fs.mkdirSync(EVIDENCE_DIR, { recursive: true });

const upload = multer({
  storage: multer.diskStorage({
    destination: (_req, _file, cb) => cb(null, EVIDENCE_DIR),
    filename: (_req, file, cb) => {
      const unique = `${Date.now()}-${crypto.randomBytes(4).toString("hex")}`;
      const ext = path.extname(file.originalname);
      cb(null, `${unique}${ext}`);
    },
  }),
  limits: { fileSize: 10 * 1024 * 1024 },
});

function toControlResponse(
  control: typeof complianceControlsTable.$inferSelect,
  frameworkName: string | null,
  groupName?: string | null,
  assetName?: string | null,
  assetScopes?: { assetId: number; assetName: string }[],
) {
  return {
    id: control.id, frameworkId: control.frameworkId, frameworkName: frameworkName ?? "",
    controlId: control.controlId, title: control.title, description: control.description,
    status: control.status, evidence: control.evidence, assignedTo: control.assignedTo,
    targetGroupId: control.targetGroupId ?? null,
    targetGroupName: groupName ?? null,
    targetAssetId: control.targetAssetId ?? null,
    targetAssetName: assetName ?? null,
    // Multi-asset scopes: array of { assetId, assetName }
    assetScopes: assetScopes ?? [],
    dueDate: control.dueDate, createdAt: control.createdAt.toISOString(),
  };
}

/** Fetch asset scopes for a list of control IDs from the junction table */
async function fetchAssetScopes(controlIds: number[]): Promise<Map<number, { assetId: number; assetName: string }[]>> {
  if (controlIds.length === 0) return new Map();
  const rows = await db.select({
    controlId: complianceControlAssetsTable.controlId,
    assetId: complianceControlAssetsTable.assetId,
    assetName: assetsTable.name,
  })
    .from(complianceControlAssetsTable)
    .leftJoin(assetsTable, eq(complianceControlAssetsTable.assetId, assetsTable.id))
    .where(inArray(complianceControlAssetsTable.controlId, controlIds));

  const map = new Map<number, { assetId: number; assetName: string }[]>();
  for (const row of rows) {
    const list = map.get(row.controlId) ?? [];
    list.push({ assetId: row.assetId, assetName: row.assetName ?? "" });
    map.set(row.controlId, list);
  }
  return map;
}

router.get("/compliance/frameworks", requireAuth, async (_req, res): Promise<void> => {
  const frameworks = await db.select().from(complianceFrameworksTable);
  res.json(frameworks.map(f => ({
    id: f.id, name: f.name, shortName: f.shortName, version: f.version,
    description: f.description, totalControls: f.totalControls,
  })));
});

router.get("/compliance/controls", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const q = ListComplianceControlsQueryParams.safeParse(req.query);
  let tenantFilter;
  if (req.user!.role === "super_admin" || req.user!.role === "admin") {
    const privIds = await getPrivilegedTenantIds(req.user!);
    if (privIds.length === 0) { res.json([]); return; }
    const qTenantId = req.query.tenantId ? parseInt(req.query.tenantId as string, 10) : NaN;
    const filtered = resolvePrivilegedTenantFilter(privIds, !isNaN(qTenantId) ? qTenantId : null);
    tenantFilter = inArray(complianceControlsTable.tenantId, filtered);
  } else if (req.user!.role === "account_manager") {
    const ids = await getAmClientTenantIds(req.user!.userId);
    if (ids.length === 0) { res.json([]); return; }
    tenantFilter = inArray(complianceControlsTable.tenantId, ids);
  } else {
    tenantFilter = eq(complianceControlsTable.tenantId, req.user!.tenantId);
  }
  const filters: any[] = tenantFilter ? [tenantFilter] : [];
  if (q.success) {
    if (q.data.frameworkId) filters.push(eq(complianceControlsTable.frameworkId, q.data.frameworkId));
    if (q.data.status) filters.push(eq(complianceControlsTable.status, q.data.status));
  }
  const controls = await db.select({
    control: complianceControlsTable,
    frameworkName: complianceFrameworksTable.name,
    groupName: assetGroupsTable.name,
    assetName: assetsTable.name,
  }).from(complianceControlsTable)
    .leftJoin(complianceFrameworksTable, eq(complianceControlsTable.frameworkId, complianceFrameworksTable.id))
    .leftJoin(assetGroupsTable, eq(complianceControlsTable.targetGroupId, assetGroupsTable.id))
    .leftJoin(assetsTable, eq(complianceControlsTable.targetAssetId, assetsTable.id))
    .where(and(...filters));

  // Fetch multi-asset scopes from junction table
  const controlIds = controls.map(c => c.control.id);
  const assetScopeMap = await fetchAssetScopes(controlIds);

  res.json(controls.map(({ control, frameworkName, groupName, assetName }) =>
    toControlResponse(control, frameworkName, groupName, assetName, assetScopeMap.get(control.id) ?? [])
  ));
});

router.get("/compliance/controls/:controlId", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const params = GetComplianceControlParams.safeParse(req.params);
  if (!params.success) { res.status(400).json({ error: params.error.message }); return; }
  const [row] = await db.select({
    control: complianceControlsTable,
    frameworkName: complianceFrameworksTable.name,
  }).from(complianceControlsTable)
    .leftJoin(complianceFrameworksTable, eq(complianceControlsTable.frameworkId, complianceFrameworksTable.id))
    .where(and(eq(complianceControlsTable.id, params.data.controlId), eq(complianceControlsTable.tenantId, req.user!.tenantId)));
  if (!row) { res.status(404).json({ error: "Control not found" }); return; }
  const assetScopeMap = await fetchAssetScopes([params.data.controlId]);
  res.json(toControlResponse(row.control, row.frameworkName, null, null, assetScopeMap.get(params.data.controlId) ?? []));
});

router.patch("/compliance/controls/:controlId", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  if (req.user!.role === "client") {
    res.status(403).json({ error: "Client users cannot modify compliance controls" }); return;
  }
  const params = UpdateComplianceControlParams.safeParse(req.params);
  if (!params.success) { res.status(400).json({ error: params.error.message }); return; }

  const rawBody = req.body as any;

  // Strip fields we handle manually so Zod doesn't see them
  const zodBody: any = { ...rawBody };
  delete zodBody.assignedTo;
  delete zodBody.targetGroupId;
  delete zodBody.targetAssetId;
  delete zodBody.assetIds;

  const parsed = UpdateComplianceControlBody.safeParse(zodBody);
  if (!parsed.success) { res.status(400).json({ error: parsed.error.message }); return; }

  const updatePayload: any = { ...parsed.data };

  // assignedTo: handle null (clearing) and any string value
  if ("assignedTo" in rawBody) {
    const v = rawBody.assignedTo;
    updatePayload.assignedTo = (typeof v === "string" && v.trim()) ? v.trim() : null;
  }

  // Legacy single-asset FK (kept for backward compat)
  if ("targetGroupId" in rawBody) {
    updatePayload.targetGroupId = rawBody.targetGroupId === null ? null : (parseInt(rawBody.targetGroupId, 10) || null);
  }
  if ("targetAssetId" in rawBody) {
    updatePayload.targetAssetId = rawBody.targetAssetId === null ? null : (parseInt(rawBody.targetAssetId, 10) || null);
  }

  const [control] = await db.update(complianceControlsTable).set(updatePayload)
    .where(and(eq(complianceControlsTable.id, params.data.controlId), eq(complianceControlsTable.tenantId, req.user!.tenantId)))
    .returning();
  if (!control) { res.status(404).json({ error: "Control not found" }); return; }

  // Multi-asset scopes: replace all entries in junction table
  if ("assetIds" in rawBody && Array.isArray(rawBody.assetIds)) {
    const newAssetIds: number[] = (rawBody.assetIds as any[])
      .map((id: any) => parseInt(String(id), 10))
      .filter((id: number) => !isNaN(id) && id > 0);

    await db.delete(complianceControlAssetsTable)
      .where(eq(complianceControlAssetsTable.controlId, params.data.controlId));

    if (newAssetIds.length > 0) {
      await db.insert(complianceControlAssetsTable)
        .values(newAssetIds.map(assetId => ({
          controlId: params.data.controlId,
          assetId,
          tenantId: req.user!.tenantId,
        })))
        .onConflictDoNothing();
    }
  }

  await logAudit(req.user!, "update_compliance_control", "compliance", control.id,
    `status: ${parsed.data.status ?? "unchanged"}${("assignedTo" in rawBody) ? ` | assignedTo: ${updatePayload.assignedTo ?? "cleared"}` : ""}`);

  const [fw] = await db.select().from(complianceFrameworksTable).where(eq(complianceFrameworksTable.id, control.frameworkId));
  let groupName: string | null = null;
  if (control.targetGroupId) {
    const [grp] = await db.select({ name: assetGroupsTable.name }).from(assetGroupsTable).where(eq(assetGroupsTable.id, control.targetGroupId));
    groupName = grp?.name ?? null;
  }
  let assetName: string | null = null;
  if (control.targetAssetId) {
    const [ast] = await db.select({ name: assetsTable.name }).from(assetsTable).where(eq(assetsTable.id, control.targetAssetId));
    assetName = ast?.name ?? null;
  }
  const assetScopeMap = await fetchAssetScopes([params.data.controlId]);
  res.json(toControlResponse(control, fw?.name ?? null, groupName, assetName, assetScopeMap.get(params.data.controlId) ?? []));
});

router.post(
  "/compliance/controls/:controlId/evidence",
  requireAuth,
  upload.array("files", 10),
  async (req: AuthenticatedRequest, res): Promise<void> => {
    if (req.user!.role === "client") {
      res.status(403).json({ error: "Client users cannot upload compliance evidence" }); return;
    }
    const controlId = parseInt(req.params.controlId as string, 10);
    if (isNaN(controlId)) { res.status(400).json({ error: "Invalid controlId" }); return; }

    const [row] = await db.select({
      control: complianceControlsTable,
      frameworkName: complianceFrameworksTable.name,
    }).from(complianceControlsTable)
      .leftJoin(complianceFrameworksTable, eq(complianceControlsTable.frameworkId, complianceFrameworksTable.id))
      .where(and(eq(complianceControlsTable.id, controlId), eq(complianceControlsTable.tenantId, req.user!.tenantId)));
    if (!row) { res.status(404).json({ error: "Control not found" }); return; }

    const files = req.files as Express.Multer.File[];
    const newFilePaths = files.map(f => ({
      name: f.originalname,
      path: f.filename,
      size: f.size,
      uploadedAt: new Date().toISOString(),
    }));

    let existing: object[] = [];
    try {
      const raw = row.control.evidence;
      if (raw) {
        const p = JSON.parse(raw);
        if (Array.isArray(p)) existing = p;
      }
    } catch {}

    const merged = [...existing, ...newFilePaths];
    const [updated] = await db.update(complianceControlsTable)
      .set({ evidence: JSON.stringify(merged) })
      .where(and(eq(complianceControlsTable.id, controlId), eq(complianceControlsTable.tenantId, req.user!.tenantId)))
      .returning();

    await logAudit(req.user!, "upload_compliance_evidence", "compliance", controlId, `${files.length} file(s) uploaded`);
    res.json(toControlResponse(updated, row.frameworkName));
  },
);

router.get(
  "/compliance/controls/:controlId/evidence/:filename",
  requireAuth,
  async (req: AuthenticatedRequest, res): Promise<void> => {
    const controlId = parseInt(req.params.controlId as string, 10);
    const filename = req.params.filename as string;
    if (isNaN(controlId) || !filename || filename.includes("..") || filename.includes("/")) {
      res.status(400).json({ error: "Invalid request" });
      return;
    }
    const [row] = await db.select({ control: complianceControlsTable })
      .from(complianceControlsTable)
      .where(and(eq(complianceControlsTable.id, controlId), eq(complianceControlsTable.tenantId, req.user!.tenantId)));
    if (!row) { res.status(404).json({ error: "Control not found" }); return; }

    let files: { name: string; path: string }[] = [];
    try { if (row.control.evidence) files = JSON.parse(row.control.evidence); } catch {}
    const fileEntry = files.find(f => f.path === filename);
    if (!fileEntry) { res.status(404).json({ error: "File not found" }); return; }

    const filePath = path.join(EVIDENCE_DIR, filename);
    if (!fs.existsSync(filePath)) { res.status(404).json({ error: "File missing on disk" }); return; }
    res.download(filePath, fileEntry.name);
  },
);

router.delete(
  "/compliance/controls/:controlId/evidence/:filename",
  requireAuth,
  async (req: AuthenticatedRequest, res): Promise<void> => {
    if (req.user!.role === "client") {
      res.status(403).json({ error: "Client users cannot delete compliance evidence" }); return;
    }
    const controlId = parseInt(req.params.controlId as string, 10);
    const filename = req.params.filename as string;
    if (isNaN(controlId) || !filename || filename.includes("..") || filename.includes("/")) {
      res.status(400).json({ error: "Invalid request" });
      return;
    }
    const [row] = await db.select({
      control: complianceControlsTable,
      frameworkName: complianceFrameworksTable.name,
    }).from(complianceControlsTable)
      .leftJoin(complianceFrameworksTable, eq(complianceControlsTable.frameworkId, complianceFrameworksTable.id))
      .where(and(eq(complianceControlsTable.id, controlId), eq(complianceControlsTable.tenantId, req.user!.tenantId)));
    if (!row) { res.status(404).json({ error: "Control not found" }); return; }

    let files: { name: string; path: string; size: number; uploadedAt: string }[] = [];
    try { if (row.control.evidence) files = JSON.parse(row.control.evidence); } catch {}
    const idx = files.findIndex(f => f.path === filename);
    if (idx === -1) { res.status(404).json({ error: "File not found in control" }); return; }

    files.splice(idx, 1);
    const filePath = path.join(EVIDENCE_DIR, filename);
    try { fs.unlinkSync(filePath); } catch {}

    const [updated] = await db.update(complianceControlsTable)
      .set({ evidence: JSON.stringify(files) })
      .where(eq(complianceControlsTable.id, controlId))
      .returning();
    await logAudit(req.user!, "delete_compliance_evidence", "compliance", controlId, `${filename} deleted`);
    res.json(toControlResponse(updated, row.frameworkName));
  },
);

// ── Create a new compliance control ──────────────────────────────────────────
router.post(
  "/compliance/controls",
  requireAuth,
  requireRole("admin", "super_admin"),
  async (req: AuthenticatedRequest, res): Promise<void> => {
    const { frameworkId, controlId, title, description, status } = req.body;
    if (!frameworkId || !controlId || !title) {
      res.status(400).json({ error: "frameworkId, controlId, and title are required" }); return;
    }
    const fwId = parseInt(String(frameworkId), 10);
    if (isNaN(fwId)) { res.status(400).json({ error: "frameworkId must be a number" }); return; }
    const [fw] = await db.select().from(complianceFrameworksTable).where(eq(complianceFrameworksTable.id, fwId));
    if (!fw) { res.status(400).json({ error: "Framework not found" }); return; }

    const tenantId = req.user!.tenantId;
    const platformId = await getPlatformTenantId();

    const validStatuses = ["non_compliant", "in_progress", "compliant", "not_applicable"];
    const controlStatus = (validStatuses.includes(String(status)) ? String(status) : "non_compliant") as any;

    const [control] = await db.insert(complianceControlsTable).values({
      tenantId,
      frameworkId: fw.id,
      controlId: String(controlId),
      title: String(title),
      description: description ? String(description) : null,
      status: controlStatus,
    }).returning();

    // Platform SA: propagate to all client tenants
    if (tenantId === platformId) {
      const clientTenants = await db.select({ id: tenantsTable.id })
        .from(tenantsTable).where(eq(tenantsTable.isPlatform, false));
      for (const ct of clientTenants) {
        const exists = await db.select({ id: complianceControlsTable.id })
          .from(complianceControlsTable)
          .where(and(
            eq(complianceControlsTable.tenantId, ct.id),
            eq(complianceControlsTable.frameworkId, fw.id),
            eq(complianceControlsTable.controlId, String(controlId)),
          )).then(r => r.length > 0);
        if (!exists) {
          await db.insert(complianceControlsTable).values({
            tenantId: ct.id,
            frameworkId: fw.id,
            controlId: String(controlId),
            title: String(title),
            description: description ? String(description) : null,
            status: "non_compliant",
          });
        }
      }
    }

    await logAudit(req.user!, "create_compliance_control", "compliance", control.id,
      `${fw.name}: ${controlId} — ${title}${tenantId === platformId ? " (propagated to clients)" : ""}`);
    res.status(201).json(toControlResponse(control, fw.name));
  },
);

// ── Delete a compliance control ───────────────────────────────────────────────
router.delete(
  "/compliance/controls/:controlId",
  requireAuth,
  requireRole("admin", "super_admin"),
  async (req: AuthenticatedRequest, res): Promise<void> => {
    if (req.user!.role === "client") {
      res.status(403).json({ error: "Client users cannot delete compliance controls" }); return;
    }
    const controlId = parseInt(req.params.controlId as string, 10);
    if (isNaN(controlId)) { res.status(400).json({ error: "Invalid controlId" }); return; }

    const tenantId = req.user!.tenantId;
    const platformId = await getPlatformTenantId();

    const [row] = await db.select({ control: complianceControlsTable })
      .from(complianceControlsTable)
      .where(and(eq(complianceControlsTable.id, controlId), eq(complianceControlsTable.tenantId, tenantId)));
    if (!row) { res.status(404).json({ error: "Control not found" }); return; }

    if (tenantId === platformId) {
      const { controlId: cId, frameworkId: fId } = row.control;
      const clientTenants = await db.select({ id: tenantsTable.id })
        .from(tenantsTable).where(eq(tenantsTable.isPlatform, false));
      for (const ct of clientTenants) {
        await db.delete(complianceControlsTable)
          .where(and(
            eq(complianceControlsTable.tenantId, ct.id),
            eq(complianceControlsTable.frameworkId, fId),
            eq(complianceControlsTable.controlId, cId),
          ));
      }
    }

    await db.delete(complianceControlsTable)
      .where(and(eq(complianceControlsTable.id, controlId), eq(complianceControlsTable.tenantId, tenantId)));

    await logAudit(req.user!, "delete_compliance_control", "compliance", controlId,
      tenantId === platformId ? "propagated deletion to client tenants" : undefined);
    res.sendStatus(204);
  },
);

router.get("/compliance/summary", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const frameworks = await db.select().from(complianceFrameworksTable);
  let summaryTenantFilter;
  if (req.user!.role === "super_admin" || req.user!.role === "admin") {
    const privIds = await getPrivilegedTenantIds(req.user!);
    const qTenantId = req.query.tenantId ? parseInt(req.query.tenantId as string, 10) : NaN;
    const filtered = resolvePrivilegedTenantFilter(privIds, !isNaN(qTenantId) ? qTenantId : null);
    summaryTenantFilter = filtered.length > 0 ? inArray(complianceControlsTable.tenantId, filtered) : eq(complianceControlsTable.tenantId, -1);
  } else if (req.user!.role === "account_manager") {
    const ids = await getAmClientTenantIds(req.user!.userId);
    summaryTenantFilter = ids.length > 0 ? inArray(complianceControlsTable.tenantId, ids) : eq(complianceControlsTable.tenantId, -1);
  } else {
    summaryTenantFilter = eq(complianceControlsTable.tenantId, req.user!.tenantId);
  }
  const controls = await db.select().from(complianceControlsTable)
    .where(summaryTenantFilter);

  const summary = frameworks.map(fw => {
    const fwControls = controls.filter(c => c.frameworkId === fw.id);
    const total = fwControls.length || fw.totalControls;
    const compliant = fwControls.filter(c => c.status === "compliant").length;
    const inProgress = fwControls.filter(c => c.status === "in_progress").length;
    const nonCompliant = fwControls.filter(c => c.status === "non_compliant").length;
    const score = total > 0 ? Math.round((compliant / total) * 100) : 0;
    return {
      frameworkId: fw.id, frameworkName: fw.name, shortName: fw.shortName,
      total, compliant, inProgress, nonCompliant, score,
    };
  });

  res.json(summary);
});

export default router;
