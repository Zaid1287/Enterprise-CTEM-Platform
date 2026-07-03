import { Router } from "express";
import { eq, and } from "drizzle-orm";
import { db, findingsTable, complianceControlsTable, complianceFrameworksTable, assetsTable, riskScoresTable, scansTable } from "@workspace/db";
import { requireAuth, denyExternalMembers, type AuthenticatedRequest } from "../lib/auth";
import {
  llmComplete, llmStream, isLLMAvailable, resolveProviderConfig,
  getAvailableProviders, streamTemplate, type Provider, type LLMMessage, type ProviderConfig,
} from "../lib/llm";
import { logger } from "../lib/logger";

const router = Router();
router.use(denyExternalMembers);

// ── Template fallbacks ──────────────────────────────────────────────────────

function templateFindingExplanation(title: string, cve: string | null, cvss: number | null, severity: string): string {
  return `## Vulnerability Analysis: ${title}

**Severity:** ${severity.toUpperCase()}${cve ? ` | **CVE:** ${cve}` : ""}${cvss ? ` | **CVSS:** ${cvss}` : ""}

### What is this vulnerability?
This ${severity}-severity finding${cve ? ` (${cve})` : ""} represents a security weakness in your environment that requires attention.

### Why does it matter?
${cvss && cvss >= 9 ? `A CVSS score of ${cvss} indicates critical risk — exploitable with minimal interaction, potentially leading to full compromise.` : cvss && cvss >= 7 ? `A CVSS score of ${cvss} indicates high-severity risk requiring prompt remediation.` : "This vulnerability presents elevated risk and should be scheduled for remediation."}

### Business Impact
Exploitation could result in unauthorized access, data exfiltration, service disruption, and reputational harm.

### Next Steps
1. Verify the vulnerability in your environment
2. Apply available vendor patches immediately for ${severity === "critical" || severity === "high" ? "critical/high findings" : "this finding"}
3. Implement compensating controls while patching is underway
4. Re-scan the asset to confirm remediation

> **To get AI-powered analysis:** Go to Account Settings → AI Settings and add an API key for OpenAI, Gemini, Anthropic, OpenRouter, or configure Ollama.`;
}

function templateRemediation(title: string, cve: string | null, severity: string) {
  return {
    steps: [
      "Identify all assets running the vulnerable component in your inventory",
      `Review vendor security advisories${cve ? ` for ${cve}` : ""} and download available patches`,
      "Implement compensating controls (WAF rules, network segmentation) while patches are prepared",
      "Test the patch in a staging/non-production environment first",
      "Schedule a maintenance window and deploy with a tested rollback plan",
      "Re-scan the affected asset to confirm the vulnerability is no longer present",
      "Update your asset inventory with the new version information",
      "Document the remediation in your change management system and close the finding",
    ],
    priority: severity === "critical" ? "Immediate (within 24 hours)" : severity === "high" ? "Urgent (within 7 days)" : severity === "medium" ? "Standard (within 30 days)" : "Low (within 90 days)",
    estimatedEffort: severity === "critical" || severity === "high" ? "2-6 hours" : "4-8 hours",
    references: [cve ? `https://nvd.nist.gov/vuln/detail/${cve}` : null, "https://owasp.org/www-community/vulnerabilities/", "https://attack.mitre.org/"].filter(Boolean),
  };
}

function templateExecSummary(critical: number, high: number, medium: number, low: number, open: number, mitigated: number, kev: number, total: number, avgCvss: number) {
  return `## Executive Security Summary

**Report Date:** ${new Date().toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric" })}

### Security Posture Overview
${critical > 0 ? "Your organisation has **critical vulnerabilities requiring immediate attention**." : high > 0 ? "Your organisation has high-severity vulnerabilities that should be addressed promptly." : "Your organisation has a manageable risk profile."} Continuous monitoring has identified **${total} total findings** across your asset inventory.

### Key Metrics
| Severity | Count |
|---|---|
| Critical | ${critical} ${critical > 0 ? "⚠️" : "✅"} |
| High | ${high} |
| Medium | ${medium} |
| Low | ${low} |
| **Total Open** | **${open}** |
| Mitigated | ${mitigated} ✅ |
| KEV (Actively Exploited) | ${kev} ${kev > 0 ? "🚨" : "✅"} |
| Avg CVSS Score | ${avgCvss.toFixed(1)} |

### Critical Risk Areas
${critical > 0 ? `**${critical} critical vulnerabilities** require remediation within 24 hours.` : "No critical vulnerabilities detected — maintain current posture."}
${kev > 0 ? `\n**${kev} findings** match CISA's Known Exploited Vulnerabilities catalog — active exploitation confirmed in the wild. These are top priority.` : ""}

### Strategic Recommendations
1. ${critical > 0 ? "Immediately remediate all critical findings (SLA: 24 hours)" : "Maintain current remediation velocity for high-severity findings"}
2. Prioritise all KEV findings regardless of internal severity rating
3. Ensure complete asset inventory coverage for accurate exposure assessment
4. Schedule quarterly penetration testing for high-risk assets
5. Review and test your incident response plan against your current threat landscape`;
}

function templateComplianceGuidance(controlId: string, title: string, frameworkName: string | null, description: string | null, status: string) {
  return `## Compliance Guidance: ${controlId} — ${title}

**Framework:** ${frameworkName ?? "Unknown"} | **Status:** ${status.replace(/_/g, " ").toUpperCase()}

### Understanding This Control
${description ?? `Control ${controlId} is part of the ${frameworkName ?? "compliance"} framework addressing security governance requirements.`}

### Implementation Steps
1. **Document current state** — Gather evidence of existing controls, policies, and procedures
2. **Gap analysis** — Compare against control requirements to identify what's missing
3. **Implement remediation** — Address gaps through policy updates and technical controls
4. **Collect evidence** — Screenshots, logs, policy documents, attestations
5. **Assign an owner** — Designate a control owner for ongoing maintenance
6. **Set review cadence** — Schedule periodic control reviews (quarterly recommended)

### Evidence Requirements
- Written policy document with version control
- Technical configuration screenshots or configuration exports
- Audit logs demonstrating control effectiveness over 90+ days
- Review sign-offs from control owner
- Training records (for personnel-related controls)

### Timeline
${status === "non_compliant" ? "**Priority:** Address within 30–60 days to close the compliance gap." : "Continue maintaining compliance and collect ongoing evidence."}`;
}

// ── Message builders ────────────────────────────────────────────────────────

function buildFindingExplainMessages(f: any): LLMMessage[] {
  return [
    { role: "system", content: `You are an expert cybersecurity analyst for a CTEM (Continuous Threat Exposure Management) platform. Analyse vulnerability findings with precision. Use Markdown with sections: ## Vulnerability Analysis, ### What is this?, ### Technical Details, ### Business Impact, ### Attack Vector, ### Exploitability. Be specific and technical.` },
    { role: "user", content: `Analyse this vulnerability:\n\n**Title:** ${f.title}\n**Severity:** ${f.severity}\n**CVE:** ${f.cve ?? "N/A"}\n**CVSS:** ${f.cvss ?? "N/A"}\n**EPSS:** ${f.epss ?? "N/A"} (exploitation probability in 30 days)\n**CWE:** ${f.cwe ?? "N/A"}\n**CISA KEV:** ${f.isKev ? "YES — actively exploited" : "No"}\n**Status:** ${f.status}\n**Description:** ${f.description ?? "None"}\n\nProvide a detailed, technical analysis.` },
  ];
}

function buildRemediationMessages(f: any): LLMMessage[] {
  return [
    { role: "system", content: `You are a senior security engineer writing remediation plans for enterprise teams. Return ONLY valid JSON — no markdown, no extra text:\n{"steps":["step1","step2"],"priority":"Immediate (within 24 hours)","estimatedEffort":"X-Y hours","references":["https://..."]}\n6-10 concrete steps. Real URLs only.` },
    { role: "user", content: `Remediation plan for:\n\n**Title:** ${f.title}\n**Severity:** ${f.severity}\n**CVE:** ${f.cve ?? "N/A"}\n**CVSS:** ${f.cvss ?? "N/A"}\n**EPSS:** ${f.epss ?? "N/A"}\n**CWE:** ${f.cwe ?? "N/A"}\n**KEV:** ${f.isKev ? "YES" : "No"}\n**Description:** ${f.description ?? "N/A"}` },
  ];
}

function buildExecSummaryMessages(data: { critical: number; high: number; medium: number; low: number; open: number; mitigated: number; kev: number; total: number; avgCvss: number }): LLMMessage[] {
  return [
    { role: "system", content: `You are a CISO-level security advisor writing executive briefings for board audiences. Use clear business language. Structure with Markdown:\n## Executive Security Summary\n### Security Posture Overview\n### Key Metrics (table)\n### Critical Risk Areas\n### Trend & Progress\n### Strategic Recommendations (3-5 bullets)\nBe honest about risk. Do not sugarcoat.` },
    { role: "user", content: `Executive security briefing for ${new Date().toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric" })}:\n\nCritical: ${data.critical} | High: ${data.high} | Medium: ${data.medium} | Low: ${data.low} | Total: ${data.total}\nOpen: ${data.open} | Mitigated: ${data.mitigated} | KEV (actively exploited): ${data.kev}\nAverage CVSS: ${data.avgCvss.toFixed(1)}\n\nWrite a board-level briefing with strategic recommendations.` },
  ];
}

function buildComplianceMessages(controlId: string, title: string, description: string | null, status: string, frameworkName: string | null): LLMMessage[] {
  return [
    { role: "system", content: `You are a certified compliance expert (CISSP, CISM, ISO 27001 Lead Auditor) for ${frameworkName ?? "security compliance"}. Provide specific, actionable guidance. Use Markdown:\n## Compliance Guidance: <ID> — <title>\n### Understanding This Control\n### Implementation Steps (numbered)\n### Evidence Requirements\n### Common Pitfalls\n### Recommended Tools` },
    { role: "user", content: `Guidance for compliance control:\n\n**Framework:** ${frameworkName ?? "Unknown"}\n**Control ID:** ${controlId}\n**Title:** ${title}\n**Description:** ${description ?? "None"}\n**Status:** ${status.replace(/_/g, " ").toUpperCase()}\n\nProvide actionable implementation guidance with concrete evidence requirements.` },
  ];
}

function buildRiskScoreMessages(asset: any, risk: any, findings: any[]): LLMMessage[] {
  const critical = findings.filter(f => f.severity === "critical").length;
  const high = findings.filter(f => f.severity === "high").length;
  const kev = findings.filter(f => f.isKev).length;
  return [
    { role: "system", content: `You are a security risk analyst explaining risk scores to security teams. Be precise and analytical. Use Markdown:\n## Risk Score Analysis: <asset name>\n### Score Breakdown\n### Key Risk Drivers\n### What This Means\n### Priority Actions` },
    { role: "user", content: `Explain this asset's risk score:\n\n**Asset:** ${asset.name} (${asset.type})\n**Risk Score:** ${risk.score?.toFixed(1) ?? "N/A"}/100\n**Risk Level:** ${risk.level?.toUpperCase()}\n**CVSS Component:** ${risk.cvssComponent?.toFixed(2) ?? "0"}\n**EPSS Component:** ${risk.epssComponent?.toFixed(2) ?? "0"}\n**KEV Bonus:** ${risk.kevBonus?.toFixed(2) ?? "0"}\n\n**Findings:** ${findings.length} total — ${critical} critical, ${high} high, ${kev} in CISA KEV\n**Business Impact:** ${asset.businessImpact ?? 5}/10\n\nExplain why this asset has this risk score and what drives it highest.` },
  ];
}

function buildScanSummaryMessages(scan: any, asset: any, findings: any[]): LLMMessage[] {
  const bySev = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) bySev[f.severity as keyof typeof bySev] = (bySev[f.severity as keyof typeof bySev] ?? 0) + 1;
  const kev = findings.filter(f => f.isKev).length;
  const topFindings = findings.filter(f => f.severity === "critical" || f.severity === "high").slice(0, 5).map(f => `- ${f.title} (${f.severity.toUpperCase()}${f.cve ? `, ${f.cve}` : ""}${f.isKev ? ", KEV" : ""})`).join("\n");
  return [
    { role: "system", content: `You are a security triage analyst reviewing scan results for a CTEM platform. Provide clear, prioritised triage analysis. Use Markdown:\n## Scan Triage: <asset>\n### Executive Triage Summary\n### Critical Findings (urgent)\n### High Priority Actions (this week)\n### Risk Assessment\n### Recommended Next Steps` },
    { role: "user", content: `Triage this security scan:\n\n**Asset:** ${asset.name} (${asset.type})\n**Scan:** #${scan.id} | Status: ${scan.status}\n**Completed:** ${scan.completedAt ? new Date(scan.completedAt).toLocaleDateString() : "In progress"}\n\n**Finding Counts:**\nCritical: ${bySev.critical} | High: ${bySev.high} | Medium: ${bySev.medium} | Low: ${bySev.low}\nTotal: ${findings.length} | In CISA KEV: ${kev}\n\n**Top Critical/High Findings:**\n${topFindings || "None"}\n\nProvide actionable triage guidance prioritised by risk.` },
  ];
}

// ── GET /ai/providers — list configured providers for user ──────────────────

router.get("/ai/providers", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  try {
    const available = await getAvailableProviders(req.user!.userId);
    res.json({
      providers: available.map(p => ({
        id: p.provider,
        name: { openai: "OpenAI", anthropic: "Anthropic", gemini: "Google Gemini", openrouter: "OpenRouter", ollama: "Ollama (Local)" }[p.provider],
        model: p.model,
        source: p.source,
        hasKey: true,
      })),
      count: available.length,
    });
  } catch (err) {
    logger.error({ err }, "Failed to list AI providers");
    res.json({ providers: [], count: 0 });
  }
});

// ── POST /ai/stream — SSE streaming for all AI actions ─────────────────────

router.post("/ai/stream", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const {
    action,
    findingId,
    controlId,
    assetId,
    scanId,
    provider: preferredProvider,
    messages: chatMessages,
  } = req.body as {
    action: string;
    findingId?: number;
    controlId?: number;
    assetId?: number;
    scanId?: number;
    provider?: Provider;
    messages?: LLMMessage[];
  };

  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.flushHeaders();

  let closed = false;
  req.on("close", () => { closed = true; });
  const send = (data: object) => { if (!closed) res.write(`data: ${JSON.stringify(data)}\n\n`); };

  try {
    const config = await resolveProviderConfig(req.user!.userId, preferredProvider ?? null);
    let messages: LLMMessage[] = [];
    let templateFallback: (() => string) | null = null;

    switch (action) {
      case "explain-finding": {
        if (!findingId) { send({ error: "findingId required", done: true }); if (!closed) res.end(); return; }
        const [f] = await db.select().from(findingsTable).where(and(eq(findingsTable.id, findingId), eq(findingsTable.tenantId, req.user!.tenantId)));
        if (!f) { send({ error: "Finding not found", done: true }); if (!closed) res.end(); return; }
        messages = buildFindingExplainMessages(f);
        templateFallback = () => templateFindingExplanation(f.title, f.cve, f.cvss, f.severity);
        break;
      }
      case "remediation": {
        if (!findingId) { send({ error: "findingId required", done: true }); if (!closed) res.end(); return; }
        const [f] = await db.select().from(findingsTable).where(and(eq(findingsTable.id, findingId), eq(findingsTable.tenantId, req.user!.tenantId)));
        if (!f) { send({ error: "Finding not found", done: true }); if (!closed) res.end(); return; }
        messages = buildRemediationMessages(f);
        templateFallback = () => JSON.stringify(templateRemediation(f.title, f.cve, f.severity), null, 2);
        break;
      }
      case "executive-summary": {
        const findings = await db.select().from(findingsTable).where(eq(findingsTable.tenantId, req.user!.tenantId));
        const critical = findings.filter(f => f.severity === "critical").length;
        const high = findings.filter(f => f.severity === "high").length;
        const medium = findings.filter(f => f.severity === "medium").length;
        const low = findings.filter(f => f.severity === "low").length;
        const open = findings.filter(f => f.status === "open").length;
        const mitigated = findings.filter(f => f.status === "mitigated").length;
        const kev = findings.filter(f => f.isKev).length;
        const avgCvss = findings.filter(f => f.cvss != null).reduce((s, f) => s + f.cvss!, 0) / (findings.filter(f => f.cvss != null).length || 1);
        const data = { critical, high, medium, low, open, mitigated, kev, total: findings.length, avgCvss };
        messages = buildExecSummaryMessages(data);
        templateFallback = () => templateExecSummary(critical, high, medium, low, open, mitigated, kev, findings.length, avgCvss);
        break;
      }
      case "compliance-guidance": {
        if (!controlId) { send({ error: "controlId required", done: true }); if (!closed) res.end(); return; }
        const [row] = await db.select({ control: complianceControlsTable, frameworkName: complianceFrameworksTable.name })
          .from(complianceControlsTable)
          .leftJoin(complianceFrameworksTable, eq(complianceControlsTable.frameworkId, complianceFrameworksTable.id))
          .where(eq(complianceControlsTable.id, controlId));
        if (!row) { send({ error: "Control not found", done: true }); if (!closed) res.end(); return; }
        messages = buildComplianceMessages(row.control.controlId, row.control.title, row.control.description ?? null, row.control.status, row.frameworkName ?? null);
        templateFallback = () => templateComplianceGuidance(row.control.controlId, row.control.title, row.frameworkName ?? null, row.control.description ?? null, row.control.status);
        break;
      }
      case "explain-risk-score": {
        if (!assetId) { send({ error: "assetId required", done: true }); if (!closed) res.end(); return; }
        const [asset] = await db.select().from(assetsTable).where(and(eq(assetsTable.id, assetId), eq(assetsTable.tenantId, req.user!.tenantId)));
        if (!asset) { send({ error: "Asset not found", done: true }); if (!closed) res.end(); return; }
        const [risk] = await db.select().from(riskScoresTable).where(eq(riskScoresTable.assetId, assetId));
        const findings = await db.select({ severity: findingsTable.severity, isKev: findingsTable.isKev, title: findingsTable.title, cve: findingsTable.cve }).from(findingsTable).where(and(eq(findingsTable.assetId, assetId), eq(findingsTable.tenantId, req.user!.tenantId)));
        messages = buildRiskScoreMessages(asset, risk ?? { score: 0, level: "low", cvssComponent: 0, epssComponent: 0, kevBonus: 0 }, findings);
        templateFallback = () => `## Risk Score Analysis: ${asset.name}\n\n**Score:** ${risk?.score?.toFixed(1) ?? 0}/100 (${risk?.level?.toUpperCase() ?? "UNKNOWN"})\n\nThis asset's risk is calculated from CVSS scores, EPSS exploitation probability, CISA KEV presence, and business impact weighting.\n\n> Configure an AI provider in Account Settings for detailed AI-powered risk explanation.`;
        break;
      }
      case "summarize-scan": {
        if (!scanId) { send({ error: "scanId required", done: true }); if (!closed) res.end(); return; }
        const [scan] = await db.select().from(scansTable).where(and(eq(scansTable.id, scanId), eq(scansTable.tenantId, req.user!.tenantId)));
        if (!scan) { send({ error: "Scan not found", done: true }); if (!closed) res.end(); return; }
        const firstAssetId = (scan.assetIds as number[])[0];
        const [asset] = firstAssetId ? await db.select().from(assetsTable).where(eq(assetsTable.id, firstAssetId)) : [];
        const findings = await db.select().from(findingsTable).where(and(eq(findingsTable.scanId, scanId), eq(findingsTable.tenantId, req.user!.tenantId)));
        messages = buildScanSummaryMessages(scan, asset ?? { name: `Scan #${scan.id}`, type: "unknown" }, findings);
        templateFallback = () => `## Scan Triage: ${asset?.name ?? `Scan #${scan.id}`}\n\n**Scan #${scan.id}** — ${findings.length} findings detected\n\nCritical: ${findings.filter(f => f.severity === "critical").length} | High: ${findings.filter(f => f.severity === "high").length} | KEV: ${findings.filter(f => f.isKev).length}\n\n> Configure an AI provider in Account Settings for detailed AI triage analysis.`;
        break;
      }
      case "chat": {
        if (!chatMessages?.length) { send({ error: "messages required", done: true }); if (!closed) res.end(); return; }
        messages = [
          { role: "system", content: "You are an expert cybersecurity analyst assistant for the Sentinelware CTEM platform. Help security teams understand vulnerabilities, risks, compliance requirements, and remediation strategies. Be concise and actionable. Use Markdown for structure." },
          ...chatMessages,
        ];
        templateFallback = () => "I'm a security AI assistant. To get AI-powered responses, please configure an API key in Account Settings → AI Settings (OpenAI, Gemini, Anthropic, OpenRouter, or Ollama).";
        break;
      }
      default:
        send({ error: `Unknown action: ${action}`, done: true });
        if (!closed) res.end();
        return;
    }

    if (!config) {
      send({ noKey: true });
      await streamTemplate(
        templateFallback!(),
        (chunk) => send({ text: chunk }),
        (usage) => send({ done: true, model: "template", usage }),
      );
    } else {
      send({ provider: config.provider, model: config.model });
      await llmStream(
        messages,
        { maxTokens: 1400 },
        config,
        (chunk) => send({ text: chunk }),
        (usage) => send({ done: true, model: `${config.provider}/${config.model}`, usage }),
      );
    }
  } catch (err) {
    logger.error({ err }, "AI stream error");
    send({ error: "AI generation failed. Please try again.", done: true });
  }

  if (!closed) res.end();
});

// ── POST /ai/explain-risk-score ─────────────────────────────────────────────

router.post("/ai/explain-risk-score", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const { assetId, provider: preferredProvider } = req.body;
  if (!assetId) { res.status(400).json({ error: "assetId is required" }); return; }

  const [asset] = await db.select().from(assetsTable).where(and(eq(assetsTable.id, assetId), eq(assetsTable.tenantId, req.user!.tenantId)));
  if (!asset) { res.status(404).json({ error: "Asset not found" }); return; }

  const [risk] = await db.select().from(riskScoresTable).where(eq(riskScoresTable.assetId, assetId));
  const findings = await db.select({ severity: findingsTable.severity, isKev: findingsTable.isKev, title: findingsTable.title, cve: findingsTable.cve }).from(findingsTable).where(and(eq(findingsTable.assetId, assetId), eq(findingsTable.tenantId, req.user!.tenantId)));

  const config = await resolveProviderConfig(req.user!.userId, preferredProvider ?? null);
  const safeRisk = risk ?? { score: 0, level: "low", cvssComponent: 0, epssComponent: 0, kevBonus: 0 };
  const messages = buildRiskScoreMessages(asset, safeRisk, findings);

  const result = await llmComplete(messages, { maxTokens: 1000 }, config);
  const content = result.text ?? `## Risk Score: ${safeRisk.score?.toFixed(1) ?? 0}/100 (${safeRisk.level?.toUpperCase()})\n\nThis score combines CVSS severity, EPSS exploitation probability, KEV status, and business impact. Configure an AI provider for detailed analysis.`;

  res.json({ content, model: config?.provider ?? "template", usage: result.usage, generatedAt: new Date().toISOString() });
});

// ── POST /ai/summarize-scan ─────────────────────────────────────────────────

router.post("/ai/summarize-scan", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const { scanId, provider: preferredProvider } = req.body;
  if (!scanId) { res.status(400).json({ error: "scanId is required" }); return; }

  const [scan] = await db.select().from(scansTable).where(and(eq(scansTable.id, scanId), eq(scansTable.tenantId, req.user!.tenantId)));
  if (!scan) { res.status(404).json({ error: "Scan not found" }); return; }

  const firstAssetId = (scan.assetIds as number[])[0];
  const [asset] = firstAssetId ? await db.select().from(assetsTable).where(eq(assetsTable.id, firstAssetId)) : [];
  const findings = await db.select().from(findingsTable).where(and(eq(findingsTable.scanId, scanId), eq(findingsTable.tenantId, req.user!.tenantId)));

  const config = await resolveProviderConfig(req.user!.userId, preferredProvider ?? null);
  const messages = buildScanSummaryMessages(scan, asset ?? { name: `Scan #${scan.id}`, type: "unknown" }, findings);

  const result = await llmComplete(messages, { maxTokens: 1000 }, config);
  const content = result.text ?? `## Scan Triage: ${asset?.name}\n\nScan #${scanId} found ${findings.length} findings. Configure an AI provider for detailed triage.`;

  res.json({ content, model: config?.provider ?? "template", usage: result.usage, generatedAt: new Date().toISOString() });
});

// ── Existing non-streaming routes (wire provider priority chain) ────────────

router.post("/ai/explain-finding", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const { findingId, provider: preferredProvider } = req.body;
  if (!findingId) { res.status(400).json({ error: "findingId is required" }); return; }

  const [finding] = await db.select().from(findingsTable).where(and(eq(findingsTable.id, findingId), eq(findingsTable.tenantId, req.user!.tenantId)));
  if (!finding) { res.status(404).json({ error: "Finding not found" }); return; }

  const config = await resolveProviderConfig(req.user!.userId, preferredProvider ?? null);
  const messages = buildFindingExplainMessages(finding);
  const result = await llmComplete(messages, { maxTokens: 1200 }, config);
  const content = result.text ?? templateFindingExplanation(finding.title, finding.cve, finding.cvss, finding.severity);

  res.json({ content, model: config?.provider ?? "template", usage: result.usage, generatedAt: new Date().toISOString() });
});

router.post("/ai/remediation", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const { findingId, provider: preferredProvider } = req.body;
  if (!findingId) { res.status(400).json({ error: "findingId is required" }); return; }

  const [finding] = await db.select().from(findingsTable).where(and(eq(findingsTable.id, findingId), eq(findingsTable.tenantId, req.user!.tenantId)));
  if (!finding) { res.status(404).json({ error: "Finding not found" }); return; }

  const config = await resolveProviderConfig(req.user!.userId, preferredProvider ?? null);
  const messages = buildRemediationMessages(finding);
  const result = await llmComplete(messages, { maxTokens: 1000 }, config);

  if (result.text) {
    try {
      const parsed = JSON.parse(result.text);
      res.json({ ...parsed, model: config?.provider ?? "template", usage: result.usage }); return;
    } catch { /* fallthrough */ }
  }
  res.json({ ...templateRemediation(finding.title, finding.cve, finding.severity), model: "template" });
});

router.post("/ai/executive-summary", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const findings = await db.select().from(findingsTable).where(eq(findingsTable.tenantId, req.user!.tenantId));
  const critical = findings.filter(f => f.severity === "critical").length;
  const high = findings.filter(f => f.severity === "high").length;
  const medium = findings.filter(f => f.severity === "medium").length;
  const low = findings.filter(f => f.severity === "low").length;
  const open = findings.filter(f => f.status === "open").length;
  const mitigated = findings.filter(f => f.status === "mitigated").length;
  const kev = findings.filter(f => f.isKev).length;
  const avgCvss = findings.filter(f => f.cvss != null).reduce((s, f) => s + f.cvss!, 0) / (findings.filter(f => f.cvss != null).length || 1);

  const { provider: preferredProvider } = req.body ?? {};
  const config = await resolveProviderConfig(req.user!.userId, preferredProvider ?? null);
  const data = { critical, high, medium, low, open, mitigated, kev, total: findings.length, avgCvss };
  const result = await llmComplete(buildExecSummaryMessages(data), { maxTokens: 1200 }, config);
  const content = result.text ?? templateExecSummary(critical, high, medium, low, open, mitigated, kev, findings.length, avgCvss);

  res.json({ content, model: config?.provider ?? "template", usage: result.usage, generatedAt: new Date().toISOString() });
});

router.post("/ai/compliance-guidance", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const { controlId, provider: preferredProvider } = req.body;
  if (!controlId) { res.status(400).json({ error: "controlId is required" }); return; }

  const [row] = await db.select({ control: complianceControlsTable, frameworkName: complianceFrameworksTable.name })
    .from(complianceControlsTable)
    .leftJoin(complianceFrameworksTable, eq(complianceControlsTable.frameworkId, complianceFrameworksTable.id))
    .where(eq(complianceControlsTable.id, controlId));
  if (!row) { res.status(404).json({ error: "Control not found" }); return; }

  const config = await resolveProviderConfig(req.user!.userId, preferredProvider ?? null);
  const messages = buildComplianceMessages(row.control.controlId, row.control.title, row.control.description ?? null, row.control.status, row.frameworkName ?? null);
  const result = await llmComplete(messages, { maxTokens: 1200 }, config);
  const content = result.text ?? templateComplianceGuidance(row.control.controlId, row.control.title, row.frameworkName ?? null, row.control.description ?? null, row.control.status);

  res.json({ content, model: config?.provider ?? "template", usage: result.usage, generatedAt: new Date().toISOString() });
});

router.get("/ai/status", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  try {
    const providers = await getAvailableProviders(req.user!.userId);
    const hasAny = providers.length > 0;
    const first = providers[0];
    res.json({
      llmEnabled: hasAny,
      model: hasAny ? first.model : "template-fallback",
      provider: hasAny ? first.provider : null,
      providersCount: providers.length,
    });
  } catch {
    res.json({ llmEnabled: isLLMAvailable(), model: isLLMAvailable() ? "gpt-4o-mini" : "template-fallback", provider: isLLMAvailable() ? "openai" : null, providersCount: isLLMAvailable() ? 1 : 0 });
  }
});

export default router;
