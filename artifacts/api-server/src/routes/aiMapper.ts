import { Router } from "express";
import { eq, and, desc, sql } from "drizzle-orm";
import * as dns from "node:dns/promises";
import {
  db, assetsTable, aiMapperScansTable, aiMapperResultsTable,
} from "@workspace/db";
import { requireAuth, denyExternalMembers, type AuthenticatedRequest } from "../lib/auth";
import { llmComplete, isLLMAvailable } from "../lib/llm";
import { geoIpBatch } from "../lib/geoIpClient";

const router = Router();
router.use(denyExternalMembers);

// ── AI service definitions ──────────────────────────────────────────────────

interface AiServiceDef {
  port: number;
  name: string;
  probePath: string;
  framework: string;
}

const AI_SERVICES: AiServiceDef[] = [
  { port: 11434, name: "ollama",      probePath: "/api/tags",          framework: "Ollama" },
  { port: 7860,  name: "gradio",      probePath: "/info",              framework: "Gradio" },
  { port: 8000,  name: "vllm",        probePath: "/v1/models",         framework: "vLLM" },
  { port: 1234,  name: "lmstudio",    probePath: "/v1/models",         framework: "LM Studio" },
  { port: 6333,  name: "qdrant",      probePath: "/",                  framework: "Qdrant" },
  { port: 8080,  name: "langserve",   probePath: "/docs",              framework: "LangServe" },
  { port: 3000,  name: "comfyui",     probePath: "/system_stats",      framework: "ComfyUI" },
  { port: 3001,  name: "flowise",     probePath: "/api/v1/chatflows",  framework: "Flowise" },
  { port: 5000,  name: "langflow",    probePath: "/api/v1/config",     framework: "LangFlow" },
  { port: 4000,  name: "litellm",     probePath: "/models",            framework: "LiteLLM" },
  { port: 5001,  name: "openai-compat", probePath: "/v1/models",       framework: "OpenAI-Compatible" },
];

interface ProbeResult {
  status: number;
  body: unknown;
  isAuth: boolean;
  corsPolicy: "open" | "restricted" | "none";
}

async function probeAiService(host: string, port: number, probePath: string): Promise<ProbeResult | null> {
  const url = `http://${host}:${port}${probePath}`;
  try {
    const res = await fetch(url, { signal: AbortSignal.timeout(3_000), redirect: "follow" });
    const isAuth = res.status === 401 || res.status === 403;
    const corsHeader = res.headers.get("access-control-allow-origin");
    const corsPolicy: "open" | "restricted" | "none" =
      corsHeader === "*" ? "open" : corsHeader ? "restricted" : "none";
    let body: unknown = null;
    try { body = await res.json(); } catch { /* non-JSON */ }
    return { status: res.status, body, isAuth, corsPolicy };
  } catch {
    return null;
  }
}

function computeRisk(
  isAuth: boolean,
  corsPolicy: string,
  modelsExposed: string[],
  toolsExposed: string[],
): { score: number; level: string } {
  let score = 4; // base: port is exposed at all
  if (!isAuth) score += 3;
  if (modelsExposed.length > 0) score += 1;
  if (toolsExposed.length > 0) score += 2;
  if (corsPolicy === "open" && !isAuth) score += 1;
  score = Math.min(10, score);
  const level =
    score >= 8 ? "critical" :
    score >= 6 ? "high" :
    score >= 4 ? "medium" :
    score >= 2 ? "low" : "info";
  return { score, level };
}

function extractModels(body: unknown, serviceName: string): string[] {
  if (!body || typeof body !== "object") return [];
  const b = body as Record<string, unknown>;
  // Ollama: { models: [{name, model}, ...] }
  if (serviceName === "ollama" && Array.isArray(b.models)) {
    return (b.models as Record<string, string>[])
      .map(m => m.name ?? m.model ?? "")
      .filter(Boolean).slice(0, 10);
  }
  // vLLM / LM Studio / LiteLLM / OpenAI-compat: { data: [{id}, ...] }
  if (Array.isArray(b.data)) {
    return (b.data as Record<string, string>[])
      .map(m => m.id ?? "")
      .filter(Boolean).slice(0, 10);
  }
  // Qdrant: { result: { collections: [{name}, ...] } }
  if (b.result && typeof b.result === "object") {
    const r = b.result as Record<string, unknown>;
    if (Array.isArray(r.collections)) {
      return (r.collections as Record<string, string>[])
        .map(c => c.name ?? "")
        .filter(Boolean).slice(0, 10);
    }
  }
  return [];
}

function extractTools(body: unknown, serviceName: string): string[] {
  if (!body || typeof body !== "object") return [];
  // Flowise: array of chatflows
  if (serviceName === "flowise" && Array.isArray(body)) {
    return (body as Record<string, string>[])
      .slice(0, 8)
      .map(f => f.name ?? "")
      .filter(Boolean);
  }
  return [];
}

async function resolveHost(rawValue: string): Promise<string | null> {
  const host = rawValue.replace(/^https?:\/\//, "").split("/")[0].split(":")[0];
  if (!host) return null;
  if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) return host; // already an IP
  try {
    const addrs = await dns.resolve4(host);
    return addrs[0] ?? null;
  } catch {
    return null;
  }
}

// ── Background scan runner ────────────────────────────────────────────────────

async function runAiMapperScan(scanId: number, tenantId: number, targetIds: number[]) {
  try {
    await db.update(aiMapperScansTable)
      .set({ status: "running" })
      .where(eq(aiMapperScansTable.id, scanId));

    const assets = targetIds.length
      ? await db.select().from(assetsTable)
          .where(and(eq(assetsTable.tenantId, tenantId),
            sql`${assetsTable.id} = ANY(${sql.raw(`ARRAY[${targetIds.join(",")}]::int[]`)})`))
      : await db.select().from(assetsTable)
          .where(eq(assetsTable.tenantId, tenantId));

    // Resolve all asset IPs up front for geo batch lookup
    const assetIpMap = new Map<number, { host: string; ip: string | null }>();
    for (const asset of assets) {
      const raw = asset.value ?? asset.name ?? "";
      const host = raw.replace(/^https?:\/\//, "").split("/")[0].split(":")[0];
      if (!host) continue;
      const ip = await resolveHost(raw);
      assetIpMap.set(asset.id, { host, ip });
    }

    const allIps = [...new Set([...assetIpMap.values()].map(v => v.ip).filter(Boolean) as string[])];
    const geoMap = await geoIpBatch(allIps);

    const inserts: {
      scanId: number; tenantId: number; assetId: number;
      url: string; host: string; port: number;
      serviceType: string; framework: string;
      isAuthenticated: boolean; corsPolicy: string;
      riskScore: number; riskLevel: string;
      modelsExposed: string[] | null; toolsExposed: string[] | null;
      rawResponse: string | null;
      ip: string | null; country: string | null; countryCode: string | null;
      city: string | null; org: string | null;
    }[] = [];

    for (const asset of assets) {
      const hostInfo = assetIpMap.get(asset.id);
      if (!hostInfo) continue;
      const { host, ip } = hostInfo;
      const geo = ip ? geoMap.get(ip) : null;

      for (const svc of AI_SERVICES) {
        const probe = await probeAiService(host, svc.port, svc.probePath);
        if (!probe || probe.status === 0) continue;

        const models = extractModels(probe.body, svc.name);
        const tools  = extractTools(probe.body, svc.name);
        const { score, level } = computeRisk(probe.isAuth, probe.corsPolicy, models, tools);

        inserts.push({
          scanId, tenantId,
          assetId:         asset.id,
          url:             `http://${host}:${svc.port}`,
          host,
          port:            svc.port,
          serviceType:     svc.name,
          framework:       svc.framework,
          isAuthenticated: probe.isAuth,
          corsPolicy:      probe.corsPolicy,
          riskScore:       score,
          riskLevel:       level,
          modelsExposed:   models.length ? models : null,
          toolsExposed:    tools.length  ? tools  : null,
          rawResponse:     probe.body ? JSON.stringify(probe.body).slice(0, 2000) : null,
          ip,
          country:     geo?.country     ?? null,
          countryCode: geo?.countryCode ?? null,
          city:        geo?.city        ?? null,
          org:         geo?.org         ?? null,
        });
      }
    }

    if (inserts.length > 0) {
      await db.insert(aiMapperResultsTable).values(inserts);
    }

    const unauthCount   = inserts.filter(r => !r.isAuthenticated).length;
    const highRiskCount = inserts.filter(r => r.riskLevel === "critical" || r.riskLevel === "high").length;

    await db.update(aiMapperScansTable).set({
      status: "completed",
      resultCount:  inserts.length,
      unauthCount,
      highRiskCount,
      completedAt: new Date(),
    }).where(eq(aiMapperScansTable.id, scanId));

  } catch (err: any) {
    await db.update(aiMapperScansTable).set({
      status: "failed",
      error: err?.message ?? "Unknown error",
      completedAt: new Date(),
    }).where(eq(aiMapperScansTable.id, scanId));
  }
}

// ── GET /ai-mapper/summary ───────────────────────────────────────────────────

router.get("/ai-mapper/summary", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const { tenantId } = req.user!;
  const [results, scans] = await Promise.all([
    db.select().from(aiMapperResultsTable).where(eq(aiMapperResultsTable.tenantId, tenantId)),
    db.select().from(aiMapperScansTable)
      .where(eq(aiMapperScansTable.tenantId, tenantId))
      .orderBy(desc(aiMapperScansTable.startedAt))
      .limit(1),
  ]);
  const serviceBreakdown: Record<string, number> = {};
  for (const r of results) {
    serviceBreakdown[r.serviceType] = (serviceBreakdown[r.serviceType] ?? 0) + 1;
  }
  res.json({
    totalEndpoints:    results.length,
    unauthEndpoints:   results.filter(r => !r.isAuthenticated).length,
    highRiskEndpoints: results.filter(r => r.riskLevel === "critical" || r.riskLevel === "high").length,
    serviceBreakdown,
    lastScanAt: scans[0]?.startedAt ?? null,
  });
});

// ── GET /ai-mapper/scans ─────────────────────────────────────────────────────

router.get("/ai-mapper/scans", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const { tenantId } = req.user!;
  const rows = await db.select().from(aiMapperScansTable)
    .where(eq(aiMapperScansTable.tenantId, tenantId))
    .orderBy(desc(aiMapperScansTable.startedAt))
    .limit(50);
  res.json(rows);
});

// ── POST /ai-mapper/scans ────────────────────────────────────────────────────

router.post("/ai-mapper/scans", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const { tenantId } = req.user!;
  const { assetIds = [] } = req.body as { assetIds?: number[] };

  let targetIds: number[] = Array.isArray(assetIds) ? assetIds.map(Number).filter(n => !isNaN(n)) : [];

  if (!targetIds.length) {
    const all = await db
      .select({ id: assetsTable.id })
      .from(assetsTable)
      .where(and(eq(assetsTable.tenantId, tenantId), eq(assetsTable.verificationStatus, "verified")));
    targetIds = all.map(a => a.id);
  }

  if (!targetIds.length) {
    res.status(400).json({ error: "No verified assets to scan. Verify at least one asset first." });
    return;
  }

  const [scan] = await db.insert(aiMapperScansTable).values({
    tenantId,
    status: "pending",
    assetIds: targetIds,
  }).returning();

  setImmediate(() => { runAiMapperScan(scan.id, tenantId, targetIds); });

  res.status(201).json(scan);
});

// ── GET /ai-mapper/scans/:id ─────────────────────────────────────────────────

router.get("/ai-mapper/scans/:id", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const { tenantId } = req.user!;
  const id = parseInt(req.params.id);
  if (isNaN(id)) { res.status(400).json({ error: "Invalid scan id" }); return; }

  const [scan] = await db.select().from(aiMapperScansTable)
    .where(and(eq(aiMapperScansTable.id, id), eq(aiMapperScansTable.tenantId, tenantId)));
  if (!scan) { res.status(404).json({ error: "Not found" }); return; }

  const results = await db.select().from(aiMapperResultsTable)
    .where(and(eq(aiMapperResultsTable.scanId, id), eq(aiMapperResultsTable.tenantId, tenantId)))
    .orderBy(desc(aiMapperResultsTable.riskScore));

  res.json({ ...scan, results });
});

// ── GET /ai-mapper/results ───────────────────────────────────────────────────

router.get("/ai-mapper/results", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const { tenantId } = req.user!;
  const { serviceType, riskLevel, page = "1", limit = "50" } = req.query as Record<string, string>;

  const conditions = [eq(aiMapperResultsTable.tenantId, tenantId)];
  if (serviceType) conditions.push(eq(aiMapperResultsTable.serviceType, serviceType));
  if (riskLevel)   conditions.push(eq(aiMapperResultsTable.riskLevel, riskLevel));

  const pageNum   = Math.max(1, parseInt(page) || 1);
  const limitNum  = Math.min(100, Math.max(1, parseInt(limit) || 50));
  const offset    = (pageNum - 1) * limitNum;

  const [rows, [{ count }]] = await Promise.all([
    db.select().from(aiMapperResultsTable)
      .where(and(...conditions as [typeof conditions[0], ...typeof conditions]))
      .orderBy(desc(aiMapperResultsTable.riskScore))
      .limit(limitNum)
      .offset(offset),
    db.select({ count: sql<number>`count(*)::int` })
      .from(aiMapperResultsTable)
      .where(and(...conditions as [typeof conditions[0], ...typeof conditions])),
  ]);

  res.json({ results: rows, total: count, page: pageNum, limit: limitNum });
});

// ── GET /ai-mapper/globe-data ────────────────────────────────────────────────

router.get("/ai-mapper/globe-data", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const { tenantId } = req.user!;

  const results = await db.select({
    country:     aiMapperResultsTable.country,
    countryCode: aiMapperResultsTable.countryCode,
    riskLevel:   aiMapperResultsTable.riskLevel,
    serviceType: aiMapperResultsTable.serviceType,
  }).from(aiMapperResultsTable)
    .where(eq(aiMapperResultsTable.tenantId, tenantId));

  const byCountry: Record<string, { country: string; countryCode: string; count: number; highRisk: number; services: Set<string> }> = {};
  for (const r of results) {
    if (!r.country || !r.countryCode) continue;
    const cc = r.countryCode;
    if (!byCountry[cc]) {
      byCountry[cc] = { country: r.country, countryCode: cc, count: 0, highRisk: 0, services: new Set() };
    }
    byCountry[cc].count++;
    if (r.riskLevel === "critical" || r.riskLevel === "high") byCountry[cc].highRisk++;
    if (r.serviceType) byCountry[cc].services.add(r.serviceType);
  }

  const points = Object.values(byCountry).map(({ services, ...rest }) => ({
    ...rest,
    services: [...services],
  }));

  res.json({ points, totalEndpoints: results.length });
});

// ── POST /ai-mapper/analyze ──────────────────────────────────────────────────

router.post("/ai-mapper/analyze", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const { tenantId } = req.user!;

  const results = await db.select().from(aiMapperResultsTable)
    .where(eq(aiMapperResultsTable.tenantId, tenantId))
    .orderBy(desc(aiMapperResultsTable.riskScore))
    .limit(20);

  if (!results.length) {
    res.json({
      analysis: "## No AI Services Discovered\n\nNo AI services have been discovered yet. Run an AI Mapper scan first to discover exposed AI infrastructure in your attack surface.",
      suggestions: [
        "Run your first AI Mapper scan by clicking 'Run Scan'",
        "Make sure you have at least one verified asset",
        "AI Mapper probes 11 common AI service ports including Ollama, Gradio, vLLM, Qdrant, LangServe, and more",
      ],
      riskLevel: "info",
      model: "template",
    });
    return;
  }

  const unauthCount = results.filter(r => !r.isAuthenticated).length;
  const critCount   = results.filter(r => r.riskLevel === "critical").length;
  const highCount   = results.filter(r => r.riskLevel === "high").length;
  const services    = [...new Set(results.map(r => r.framework).filter(Boolean))];
  const topRisks    = results.slice(0, 5)
    .map(r => `- ${r.url} (${r.framework ?? r.serviceType}, ${r.riskLevel} risk, auth: ${r.isAuthenticated ? "yes" : "NO"})`)
    .join("\n");

  if (isLLMAvailable()) {
    const summary = `${results.length} AI services discovered. ${unauthCount} unauthenticated. Services: ${services.join(", ")}.`;
    const content = await llmComplete([
      {
        role: "system",
        content: `You are an expert AI security researcher. Analyze the exposed AI infrastructure and return ONLY valid JSON with these fields:
- analysis: string (markdown, 3-5 paragraphs)
- suggestions: string[] (5 actionable items)
- riskLevel: "critical" | "high" | "medium" | "low" | "info"`,
      },
      {
        role: "user",
        content: `Analyze this AI attack surface:\n\nSummary: ${summary}\n\nTop risk endpoints:\n${topRisks}`,
      },
    ], { maxTokens: 900 });

    if (content) {
      try {
        const parsed = JSON.parse(content);
        res.json({ ...parsed, model: "gpt-4o-mini" });
        return;
      } catch { /* fall through to template */ }
    }
  }

  const overallRisk = critCount > 0 ? "critical" : highCount > 0 ? "high" : "medium";

  res.json({
    analysis: `## AI Attack Surface Analysis

**${results.length} AI services** discovered across your infrastructure — ${unauthCount} are **unauthenticated** and accessible without credentials.

### Exposed Services
${services.map(s => `- **${s}**`).join("\n")}

### Top Risk Endpoints
${topRisks}

### Risk Summary
- **${critCount} Critical** / **${highCount} High** risk endpoints need immediate attention
- Unauthenticated AI endpoints expose model inference, data, and potentially tool execution to the public internet
- Open CORS policies allow any origin to query your AI models`,
    suggestions: [
      "Enable authentication on all exposed AI service endpoints immediately",
      "Restrict Ollama and vLLM instances to localhost or VPN-only access via firewall rules",
      "Review CORS policies — open CORS exposes model APIs to any browser origin",
      "Implement API key authentication and rate limiting to prevent model abuse",
      "Audit model access logs for unauthorized inference requests and cost overruns",
    ],
    riskLevel: overallRisk,
    model: "template",
  });
});

export default router;
