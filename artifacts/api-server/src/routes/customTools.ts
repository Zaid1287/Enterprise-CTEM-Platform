import { Router } from "express";
import { exec } from "child_process";
import { promisify } from "util";
import { writeFile, unlink } from "fs/promises";
import { eq, and, desc } from "drizzle-orm";
import {
  db,
  customScriptsTable,
  customScriptAssignmentsTable,
  customScriptRunsTable,
  customNucleiTemplatesTable,
  customNucleiTemplateAssignmentsTable,
  assetsTable,
} from "@workspace/db";
import { requireAuth, type AuthenticatedRequest } from "../lib/auth";
import { logger } from "../lib/logger";
import { logAudit } from "../lib/audit";

const execAsync = promisify(exec);
const router = Router();

// ── Interpreter map ───────────────────────────────────────────────────────────
const INTERPRETERS: Record<string, string> = {
  bash:   "bash",
  sh:     "sh",
  python: "python3",
  node:   "node",
};

// ═══════════════════════════════════════════════════════════════════════════════
// CUSTOM SCRIPTS
// ═══════════════════════════════════════════════════════════════════════════════

// List all custom scripts
router.get("/custom-scripts", requireAuth, async (req: AuthenticatedRequest, res) => {
  const { tenantId } = req.user!;
  const scripts = await db.select().from(customScriptsTable)
    .where(eq(customScriptsTable.tenantId, tenantId))
    .orderBy(desc(customScriptsTable.createdAt));
  res.json(scripts);
});

// Create custom script
router.post("/custom-scripts", requireAuth, async (req: AuthenticatedRequest, res) => {
  const { tenantId, userId } = req.user!;
  const { name, description, language = "bash", content, timeout = 60 } = req.body;
  if (!name || !content) { res.status(400).json({ error: "name and content are required" }); return; }
  if (!INTERPRETERS[language]) { res.status(400).json({ error: "language must be bash, sh, python, or node" }); return; }
  const [script] = await db.insert(customScriptsTable).values({
    tenantId, name, description, language, content, timeout: Number(timeout) || 60,
    createdBy: userId as any,
  }).returning();
  await logAudit(req.user!, "custom_script_created", "custom_script", script.id, JSON.stringify({ name }), req.ip ?? "");
  res.status(201).json(script);
});

// Get single custom script
router.get("/custom-scripts/:id", requireAuth, async (req: AuthenticatedRequest, res) => {
  const { tenantId } = req.user!;
  const [script] = await db.select().from(customScriptsTable)
    .where(and(eq(customScriptsTable.id, Number(req.params.id)), eq(customScriptsTable.tenantId, tenantId)));
  if (!script) { res.status(404).json({ error: "Script not found" }); return; }
  res.json(script);
});

// Update custom script
router.patch("/custom-scripts/:id", requireAuth, async (req: AuthenticatedRequest, res) => {
  const { tenantId } = req.user!;
  const { name, description, language, content, timeout } = req.body;
  const [existing] = await db.select({ id: customScriptsTable.id })
    .from(customScriptsTable)
    .where(and(eq(customScriptsTable.id, Number(req.params.id)), eq(customScriptsTable.tenantId, tenantId)));
  if (!existing) { res.status(404).json({ error: "Script not found" }); return; }
  if (language && !INTERPRETERS[language]) { res.status(400).json({ error: "Invalid language" }); return; }
  const [updated] = await db.update(customScriptsTable)
    .set({ name, description, language, content, timeout: timeout ? Number(timeout) : undefined })
    .where(eq(customScriptsTable.id, existing.id))
    .returning();
  res.json(updated);
});

// Delete custom script
router.delete("/custom-scripts/:id", requireAuth, async (req: AuthenticatedRequest, res) => {
  const { tenantId } = req.user!;
  const [existing] = await db.select({ id: customScriptsTable.id })
    .from(customScriptsTable)
    .where(and(eq(customScriptsTable.id, Number(req.params.id)), eq(customScriptsTable.tenantId, tenantId)));
  if (!existing) { res.status(404).json({ error: "Script not found" }); return; }
  // Delete child records first (runs have no onDelete cascade in schema)
  await db.delete(customScriptRunsTable).where(eq(customScriptRunsTable.scriptId, existing.id));
  await db.delete(customScriptAssignmentsTable).where(eq(customScriptAssignmentsTable.scriptId, existing.id));
  await db.delete(customScriptsTable).where(eq(customScriptsTable.id, existing.id));
  await logAudit(req.user!, "custom_script_deleted", "custom_script", existing.id, "", req.ip ?? "");
  res.status(204).send();
});

// List assignments (assets assigned to a script)
router.get("/custom-scripts/:id/assignments", requireAuth, async (req: AuthenticatedRequest, res) => {
  const { tenantId } = req.user!;
  const scriptId = Number(req.params.id);
  const rows = await db.select({ assignment: customScriptAssignmentsTable, asset: assetsTable })
    .from(customScriptAssignmentsTable)
    .innerJoin(assetsTable, eq(assetsTable.id, customScriptAssignmentsTable.assetId))
    .where(and(eq(customScriptAssignmentsTable.scriptId, scriptId), eq(customScriptAssignmentsTable.tenantId, tenantId)));
  res.json(rows.map(r => ({ ...r.assignment, asset: r.asset })));
});

// Assign script to asset(s)
router.post("/custom-scripts/:id/assignments", requireAuth, async (req: AuthenticatedRequest, res) => {
  const { tenantId } = req.user!;
  const scriptId = Number(req.params.id);
  const assetIds: number[] = Array.isArray(req.body.assetIds) ? req.body.assetIds : [req.body.assetId];
  if (!assetIds.length) { res.status(400).json({ error: "assetIds required" }); return; }
  const [script] = await db.select({ id: customScriptsTable.id })
    .from(customScriptsTable)
    .where(and(eq(customScriptsTable.id, scriptId), eq(customScriptsTable.tenantId, tenantId)));
  if (!script) { res.status(404).json({ error: "Script not found" }); return; }
  const inserts = assetIds.map(assetId => ({ tenantId, scriptId, assetId }));
  await db.insert(customScriptAssignmentsTable).values(inserts).onConflictDoNothing();
  res.status(201).json({ assigned: assetIds.length });
});

// Remove assignment
router.delete("/custom-scripts/:id/assignments/:assetId", requireAuth, async (req: AuthenticatedRequest, res) => {
  const { tenantId } = req.user!;
  await db.delete(customScriptAssignmentsTable).where(
    and(
      eq(customScriptAssignmentsTable.scriptId, Number(req.params.id)),
      eq(customScriptAssignmentsTable.assetId, Number(req.params.assetId)),
      eq(customScriptAssignmentsTable.tenantId, tenantId),
    ),
  );
  res.status(204).send();
});

// List run history for a script
router.get("/custom-scripts/:id/runs", requireAuth, async (req: AuthenticatedRequest, res) => {
  const { tenantId } = req.user!;
  const limit = Math.min(Number(req.query.limit) || 50, 200);
  const runs = await db.select().from(customScriptRunsTable)
    .where(and(eq(customScriptRunsTable.scriptId, Number(req.params.id)), eq(customScriptRunsTable.tenantId, tenantId)))
    .orderBy(desc(customScriptRunsTable.createdAt))
    .limit(limit);
  res.json({ data: runs, total: runs.length });
});

// List scripts assigned to a specific asset
router.get("/assets/:assetId/custom-scripts", requireAuth, async (req: AuthenticatedRequest, res) => {
  const { tenantId } = req.user!;
  const rows = await db.select({ script: customScriptsTable, assignment: customScriptAssignmentsTable })
    .from(customScriptAssignmentsTable)
    .innerJoin(customScriptsTable, eq(customScriptsTable.id, customScriptAssignmentsTable.scriptId))
    .where(and(
      eq(customScriptAssignmentsTable.assetId, Number(req.params.assetId)),
      eq(customScriptAssignmentsTable.tenantId, tenantId),
    ));
  res.json(rows.map(r => r.script));
});

// Run a custom script manually against an asset
router.post("/custom-scripts/:id/run", requireAuth, async (req: AuthenticatedRequest, res) => {
  const { tenantId } = req.user!;
  const scriptId = Number(req.params.id);
  const assetId = Number(req.body.assetId);
  if (!assetId) { res.status(400).json({ error: "assetId required" }); return; }

  const [[script], [asset]] = await Promise.all([
    db.select().from(customScriptsTable).where(and(eq(customScriptsTable.id, scriptId), eq(customScriptsTable.tenantId, tenantId))),
    db.select({ value: assetsTable.value, name: assetsTable.name }).from(assetsTable).where(and(eq(assetsTable.id, assetId), eq(assetsTable.tenantId, tenantId))),
  ]);
  if (!script) { res.status(404).json({ error: "Script not found" }); return; }
  if (!asset) { res.status(404).json({ error: "Asset not found" }); return; }

  const [run] = await db.insert(customScriptRunsTable).values({
    tenantId, scriptId, assetId, scanId: null,
    status: "running", startedAt: new Date(),
  }).returning();

  res.status(202).json({ runId: run.id });

  setImmediate(async () => {
    const tmpFile = `/tmp/cscript-${scriptId}-${run.id}-${Date.now()}`;
    try {
      await writeFile(tmpFile, script.content, { mode: 0o755 });
      const interpreter = INTERPRETERS[script.language] ?? "bash";
      const { stdout, stderr } = await execAsync(`${interpreter} "${tmpFile}"`, {
        timeout: (script.timeout || 60) * 1000,
        env: {
          ...process.env,
          TARGET: asset.value ?? "",
          DOMAIN: (asset.value ?? "").replace(/^https?:\/\//, "").split("/")[0]!,
          ASSET_ID: String(assetId),
          ASSET_NAME: asset.name ?? "",
        },
      });
      await db.update(customScriptRunsTable).set({ status: "completed", stdout, stderr, exitCode: 0, completedAt: new Date() }).where(eq(customScriptRunsTable.id, run.id));
    } catch (err: any) {
      const exitCode: number = err?.code ?? 1;
      await db.update(customScriptRunsTable).set({
        status: "failed", stdout: err?.stdout ?? null, stderr: err?.stderr ?? err?.message ?? null,
        exitCode, completedAt: new Date(),
      }).where(eq(customScriptRunsTable.id, run.id));
      logger.warn({ err: err?.message, scriptId, assetId }, "Custom script run failed");
    } finally {
      unlink(tmpFile).catch(() => {});
    }
  });
});

// Get a single script run
router.get("/custom-script-runs/:id", requireAuth, async (req: AuthenticatedRequest, res) => {
  const { tenantId } = req.user!;
  const [run] = await db.select().from(customScriptRunsTable)
    .where(and(eq(customScriptRunsTable.id, Number(req.params.id)), eq(customScriptRunsTable.tenantId, tenantId)));
  if (!run) { res.status(404).json({ error: "Run not found" }); return; }
  res.json(run);
});


// ═══════════════════════════════════════════════════════════════════════════════
// CUSTOM NUCLEI TEMPLATES
// ═══════════════════════════════════════════════════════════════════════════════

// List templates
router.get("/custom-nuclei-templates", requireAuth, async (req: AuthenticatedRequest, res) => {
  const { tenantId } = req.user!;
  const templates = await db.select().from(customNucleiTemplatesTable)
    .where(eq(customNucleiTemplatesTable.tenantId, tenantId))
    .orderBy(desc(customNucleiTemplatesTable.createdAt));
  res.json(templates);
});

// Create template
router.post("/custom-nuclei-templates", requireAuth, async (req: AuthenticatedRequest, res) => {
  const { tenantId, userId } = req.user!;
  const { name, description, content } = req.body;
  if (!name || !content) { res.status(400).json({ error: "name and content (YAML) are required" }); return; }
  if (!content.includes("id:") || !content.includes("requests:") && !content.includes("http:")) {
    res.status(400).json({ error: "Invalid Nuclei template YAML — must include id: and http:/requests: sections" }); return;
  }
  const [tmpl] = await db.insert(customNucleiTemplatesTable).values({
    tenantId, name, description, content, createdBy: userId as any,
  }).returning();
  await logAudit(req.user!, "nuclei_template_created", "custom_nuclei_template", tmpl.id, JSON.stringify({ name }), req.ip ?? "");
  res.status(201).json(tmpl);
});

// Get one template
router.get("/custom-nuclei-templates/:id", requireAuth, async (req: AuthenticatedRequest, res) => {
  const { tenantId } = req.user!;
  const [tmpl] = await db.select().from(customNucleiTemplatesTable)
    .where(and(eq(customNucleiTemplatesTable.id, Number(req.params.id)), eq(customNucleiTemplatesTable.tenantId, tenantId)));
  if (!tmpl) { res.status(404).json({ error: "Template not found" }); return; }
  res.json(tmpl);
});

// Update template
router.patch("/custom-nuclei-templates/:id", requireAuth, async (req: AuthenticatedRequest, res) => {
  const { tenantId } = req.user!;
  const { name, description, content } = req.body;
  const [existing] = await db.select({ id: customNucleiTemplatesTable.id })
    .from(customNucleiTemplatesTable)
    .where(and(eq(customNucleiTemplatesTable.id, Number(req.params.id)), eq(customNucleiTemplatesTable.tenantId, tenantId)));
  if (!existing) { res.status(404).json({ error: "Template not found" }); return; }
  const [updated] = await db.update(customNucleiTemplatesTable)
    .set({ name, description, content })
    .where(eq(customNucleiTemplatesTable.id, existing.id))
    .returning();
  res.json(updated);
});

// Delete template
router.delete("/custom-nuclei-templates/:id", requireAuth, async (req: AuthenticatedRequest, res) => {
  const { tenantId } = req.user!;
  const [existing] = await db.select({ id: customNucleiTemplatesTable.id })
    .from(customNucleiTemplatesTable)
    .where(and(eq(customNucleiTemplatesTable.id, Number(req.params.id)), eq(customNucleiTemplatesTable.tenantId, tenantId)));
  if (!existing) { res.status(404).json({ error: "Template not found" }); return; }
  await db.delete(customNucleiTemplatesTable).where(eq(customNucleiTemplatesTable.id, existing.id));
  res.status(204).send();
});

// List assignments for a template
router.get("/custom-nuclei-templates/:id/assignments", requireAuth, async (req: AuthenticatedRequest, res) => {
  const { tenantId } = req.user!;
  const templateId = Number(req.params.id);
  const rows = await db.select({ assignment: customNucleiTemplateAssignmentsTable, asset: assetsTable })
    .from(customNucleiTemplateAssignmentsTable)
    .innerJoin(assetsTable, eq(assetsTable.id, customNucleiTemplateAssignmentsTable.assetId))
    .where(and(eq(customNucleiTemplateAssignmentsTable.templateId, templateId), eq(customNucleiTemplateAssignmentsTable.tenantId, tenantId)));
  res.json(rows.map(r => ({ ...r.assignment, asset: r.asset })));
});

// Assign template to asset(s)
router.post("/custom-nuclei-templates/:id/assignments", requireAuth, async (req: AuthenticatedRequest, res) => {
  const { tenantId } = req.user!;
  const templateId = Number(req.params.id);
  const assetIds: number[] = Array.isArray(req.body.assetIds) ? req.body.assetIds : [req.body.assetId];
  if (!assetIds.length) { res.status(400).json({ error: "assetIds required" }); return; }
  const [tmpl] = await db.select({ id: customNucleiTemplatesTable.id })
    .from(customNucleiTemplatesTable)
    .where(and(eq(customNucleiTemplatesTable.id, templateId), eq(customNucleiTemplatesTable.tenantId, tenantId)));
  if (!tmpl) { res.status(404).json({ error: "Template not found" }); return; }
  await db.insert(customNucleiTemplateAssignmentsTable)
    .values(assetIds.map(assetId => ({ tenantId, templateId, assetId })))
    .onConflictDoNothing();
  res.status(201).json({ assigned: assetIds.length });
});

// Remove assignment
router.delete("/custom-nuclei-templates/:id/assignments/:assetId", requireAuth, async (req: AuthenticatedRequest, res) => {
  const { tenantId } = req.user!;
  await db.delete(customNucleiTemplateAssignmentsTable).where(
    and(
      eq(customNucleiTemplateAssignmentsTable.templateId, Number(req.params.id)),
      eq(customNucleiTemplateAssignmentsTable.assetId, Number(req.params.assetId)),
      eq(customNucleiTemplateAssignmentsTable.tenantId, tenantId),
    ),
  );
  res.status(204).send();
});

// List templates assigned to an asset
router.get("/assets/:assetId/custom-nuclei-templates", requireAuth, async (req: AuthenticatedRequest, res) => {
  const { tenantId } = req.user!;
  const rows = await db.select({ template: customNucleiTemplatesTable })
    .from(customNucleiTemplateAssignmentsTable)
    .innerJoin(customNucleiTemplatesTable, eq(customNucleiTemplatesTable.id, customNucleiTemplateAssignmentsTable.templateId))
    .where(and(
      eq(customNucleiTemplateAssignmentsTable.assetId, Number(req.params.assetId)),
      eq(customNucleiTemplateAssignmentsTable.tenantId, tenantId),
    ));
  res.json(rows.map(r => r.template));
});

export default router;
