import { Router } from "express";
import { eq } from "drizzle-orm";
import { db, findingsTable, complianceControlsTable, complianceFrameworksTable } from "@workspace/db";
import { requireAuth, denyExternalMembers, type AuthenticatedRequest } from "../lib/auth";
import { llmComplete, isLLMAvailable } from "../lib/llm";

const router = Router();
router.use(denyExternalMembers);

// ── Template fallbacks (used when OPENAI_API_KEY is absent) ────────────────────

function templateFindingExplanation(title: string, cve: string | null, cvss: number | null, severity: string): string {
  return `## Vulnerability Analysis: ${title}

**Severity:** ${severity.toUpperCase()}${cve ? ` | **CVE:** ${cve}` : ""}${cvss ? ` | **CVSS Score:** ${cvss}` : ""}

### What is this vulnerability?
This finding represents a ${severity}-severity security issue${cve ? ` tracked as ${cve}` : ""} in your environment. ${
    severity === "critical" || severity === "high"
      ? "This is a high-priority vulnerability that poses significant risk and should be remediated immediately."
      : "This vulnerability should be addressed as part of your regular vulnerability management program."
  }

### Why does it matter?
${cvss && cvss >= 9.0 ? `A CVSS score of ${cvss} indicates a critical vulnerability exploitable with minimal user interaction, potentially leading to full system compromise.` :
  cvss && cvss >= 7.0 ? `A CVSS score of ${cvss} indicates a high-severity vulnerability requiring prompt attention.` :
  "This vulnerability presents a moderate risk that should be scheduled for remediation."}

### Business Impact
Exploitation could lead to unauthorized access, data breaches, financial losses, and reputational damage. ${
    severity === "critical" ? "Immediate action is required." : "Schedule remediation within your next maintenance window."
  }

### Attack Vector
Attackers with ${cvss && cvss >= 9.0 ? "no" : "limited"} prior access could exploit this vulnerability, making it a priority for your security team.`;
}

function templateRemediation(title: string, cve: string | null, severity: string) {
  return {
    steps: [
      `Assess the scope of affected systems running the vulnerable component`,
      `Review vendor security advisories${cve ? ` for ${cve}` : ""} and apply available patches`,
      `If no patch is available, implement compensating controls (WAF rules, network segmentation)`,
      `Test the patch in a non-production environment before deploying to production`,
      `Deploy during a maintenance window with a rollback plan prepared`,
      `Verify remediation by re-scanning the affected asset`,
      `Update your asset inventory with the new version information`,
      `Document the remediation in your change management system`,
    ],
    priority: severity === "critical" ? "Immediate (within 24 hours)" :
              severity === "high" ? "Urgent (within 7 days)" :
              severity === "medium" ? "Standard (within 30 days)" : "Low (within 90 days)",
    estimatedEffort: severity === "critical" ? "2-4 hours" : "4-8 hours",
    references: [
      cve ? `https://nvd.nist.gov/vuln/detail/${cve}` : null,
      "https://owasp.org/www-community/vulnerabilities/",
      "https://attack.mitre.org/",
    ].filter(Boolean),
  };
}

// ── Routes ─────────────────────────────────────────────────────────────────────

router.post("/ai/explain-finding", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const { findingId } = req.body;
  if (!findingId) { res.status(400).json({ error: "findingId is required" }); return; }

  const [finding] = await db.select().from(findingsTable).where(eq(findingsTable.id, findingId));
  if (!finding) { res.status(404).json({ error: "Finding not found" }); return; }

  let content: string;
  const usingLLM = isLLMAvailable();

  if (usingLLM) {
    const result = await llmComplete([
      {
        role: "system",
        content: `You are an expert cybersecurity analyst specializing in vulnerability assessment for a Continuous Threat Exposure Management (CTEM) platform. 
Provide clear, actionable security analysis in Markdown. Structure your response with these sections:
## Vulnerability Analysis: <title>
### What is this vulnerability?
### Technical Details
### Why does it matter?
### Business Impact
### Attack Vector & Exploitability
Be specific, technical, and accurate. Reference the CVE/CVSS data provided.`,
      },
      {
        role: "user",
        content: `Analyze this vulnerability finding from our security platform:

**Title:** ${finding.title}
**Severity:** ${finding.severity}
**CVE:** ${finding.cve ?? "N/A"}
**CVSS Score:** ${finding.cvss ?? "N/A"}
**EPSS Score:** ${finding.epss ?? "N/A"} (probability of exploitation in next 30 days)
**CWE:** ${finding.cwe ?? "N/A"}
**In CISA KEV (Known Exploited Vulnerabilities):** ${finding.isKev ? "YES — actively exploited in the wild" : "No"}
**Status:** ${finding.status}
**Description:** ${finding.description ?? "No additional description provided"}

Provide a comprehensive analysis explaining the vulnerability, its technical nature, business impact, and exploitability risk.`,
      },
    ], { maxTokens: 1200 });

    content = result ?? templateFindingExplanation(finding.title, finding.cve, finding.cvss, finding.severity);
  } else {
    content = templateFindingExplanation(finding.title, finding.cve, finding.cvss, finding.severity);
  }

  res.json({ content, model: usingLLM ? "gpt-4o-mini" : "ctem-template-v1", generatedAt: new Date().toISOString() });
});

router.post("/ai/remediation", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const { findingId } = req.body;
  if (!findingId) { res.status(400).json({ error: "findingId is required" }); return; }

  const [finding] = await db.select().from(findingsTable).where(eq(findingsTable.id, findingId));
  if (!finding) { res.status(404).json({ error: "Finding not found" }); return; }

  const usingLLM = isLLMAvailable();

  if (usingLLM) {
    const result = await llmComplete([
      {
        role: "system",
        content: `You are a senior security engineer creating actionable remediation plans for enterprise security teams.
Return ONLY valid JSON matching this exact structure (no markdown, no extra text):
{
  "steps": ["step 1", "step 2", ...],
  "priority": "Immediate (within 24 hours)" | "Urgent (within 7 days)" | "Standard (within 30 days)" | "Low (within 90 days)",
  "estimatedEffort": "X-Y hours",
  "references": ["https://...", ...]
}
Steps should be specific and technical. Include 6-10 concrete steps. References must be real, working URLs.`,
      },
      {
        role: "user",
        content: `Create a remediation plan for this vulnerability:

**Title:** ${finding.title}
**Severity:** ${finding.severity}
**CVE:** ${finding.cve ?? "N/A"}
**CVSS:** ${finding.cvss ?? "N/A"}
**EPSS:** ${finding.epss ?? "N/A"}
**CWE:** ${finding.cwe ?? "N/A"}
**In CISA KEV:** ${finding.isKev ? "YES — actively exploited" : "No"}
**Description:** ${finding.description ?? "N/A"}
**Current Status:** ${finding.status}

Provide a prioritized, step-by-step remediation plan with realistic time estimates.`,
      },
    ], { maxTokens: 1000 });

    if (result) {
      try {
        const parsed = JSON.parse(result);
        res.json({ ...parsed, model: "gpt-4o-mini" });
        return;
      } catch {
        // Fall through to template
      }
    }
  }

  const template = templateRemediation(finding.title, finding.cve, finding.severity);
  res.json({ ...template, model: "ctem-template-v1" });
});

router.post("/ai/executive-summary", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const findings = await db.select().from(findingsTable).where(eq(findingsTable.tenantId, req.user!.tenantId));

  const critical = findings.filter(f => f.severity === "critical").length;
  const high     = findings.filter(f => f.severity === "high").length;
  const medium   = findings.filter(f => f.severity === "medium").length;
  const low      = findings.filter(f => f.severity === "low").length;
  const open     = findings.filter(f => f.status === "open").length;
  const mitigated = findings.filter(f => f.status === "mitigated" || f.status === "resolved").length;
  const kev      = findings.filter(f => f.isKev).length;
  const avgCvss  = findings.filter(f => f.cvss != null).reduce((s, f) => s + f.cvss!, 0) / (findings.filter(f => f.cvss != null).length || 1);

  const usingLLM = isLLMAvailable();

  if (usingLLM) {
    const result = await llmComplete([
      {
        role: "system",
        content: `You are a CISO-level security advisor writing an executive security briefing for a board/leadership audience.
Use clear, business-focused language. Avoid jargon where possible. Structure with Markdown:
## Executive Security Summary
### Security Posture Overview
### Key Metrics  
### Critical Risk Areas
### Trend & Progress
### Strategic Recommendations (3-5 bullet points)
Be honest about the risk level. Do not sugarcoat critical findings.`,
      },
      {
        role: "user",
        content: `Generate an executive security summary for our organization based on current vulnerability data:

**Report Date:** ${new Date().toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric" })}

**Vulnerability Breakdown:**
- Critical: ${critical}
- High: ${high}
- Medium: ${medium}
- Low: ${low}
- Total: ${findings.length}

**Status:**
- Open (unresolved): ${open}
- Mitigated/Resolved: ${mitigated}

**Risk Indicators:**
- CISA Known Exploited Vulnerabilities (KEV): ${kev} ${kev > 0 ? "⚠️ — these are being actively exploited in the wild" : ""}
- Average CVSS Score: ${avgCvss.toFixed(1)}

Write an executive briefing that accurately reflects our security posture and provides actionable strategic recommendations.`,
      },
    ], { maxTokens: 1200 });

    if (result) {
      res.json({ content: result, model: "gpt-4o-mini", generatedAt: new Date().toISOString() });
      return;
    }
  }

  // Template fallback
  const content = `## Executive Security Summary

**Report Date:** ${new Date().toLocaleDateString()}  
**Classification:** Confidential

### Security Posture Overview
${critical > 0 ? `Your organization has **critical vulnerabilities requiring immediate attention**.` : "Your organization has manageable risk levels."} Continuous monitoring has identified **${findings.length} total findings** across your asset inventory.

### Key Metrics
| Severity | Count |
|----------|-------|
| Critical | ${critical} ${critical > 0 ? "⚠️" : "✅"} |
| High | ${high} |
| Medium | ${medium} |
| Low | ${low} |
| **Total Open** | **${open}** |
| KEV (Actively Exploited) | ${kev} ${kev > 0 ? "🚨" : "✅"} |

### Critical Risk Areas
${critical > 0 ? `**${critical} critical vulnerabilities** pose an immediate threat and must be remediated within 24 hours.` : "No critical vulnerabilities detected."}
${kev > 0 ? `**${kev} findings** match CISA's Known Exploited Vulnerabilities catalog — active exploitation confirmed in the wild.` : ""}

### Strategic Recommendations
1. ${critical > 0 ? "Immediately address all critical-severity findings (SLA: 24 hours)" : "Maintain current remediation velocity"}
2. Prioritize KEV findings regardless of internal severity rating
3. Ensure complete asset inventory coverage for accurate exposure assessment
4. Schedule penetration testing for high-risk assets quarterly
5. Review and test incident response procedures`;

  res.json({ content, model: "ctem-template-v1", generatedAt: new Date().toISOString() });
});

router.post("/ai/compliance-guidance", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const { controlId } = req.body;
  if (!controlId) { res.status(400).json({ error: "controlId is required" }); return; }

  const [row] = await db.select({
    control: complianceControlsTable,
    frameworkName: complianceFrameworksTable.name,
  }).from(complianceControlsTable)
    .leftJoin(complianceFrameworksTable, eq(complianceControlsTable.frameworkId, complianceFrameworksTable.id))
    .where(eq(complianceControlsTable.id, controlId));

  if (!row) { res.status(404).json({ error: "Control not found" }); return; }

  const usingLLM = isLLMAvailable();

  if (usingLLM) {
    const result = await llmComplete([
      {
        role: "system",
        content: `You are a certified compliance expert (CISSP, CISM, ISO 27001 Lead Auditor) specializing in ${row.frameworkName ?? "security compliance"}.
Provide specific, actionable implementation guidance. Use Markdown:
## Compliance Guidance: <control ID> — <title>
### Understanding This Control
### Implementation Steps (numbered, specific)
### Evidence Requirements (concrete list)
### Common Pitfalls
### Recommended Tools & Resources
Be practical. Reference real tools, templates, and processes. Tailor to the control's current status.`,
      },
      {
        role: "user",
        content: `Provide implementation guidance for this compliance control:

**Framework:** ${row.frameworkName ?? "Unknown"}
**Control ID:** ${row.control.controlId}
**Title:** ${row.control.title}
**Description:** ${row.control.description ?? "No description provided"}
**Current Status:** ${row.control.status.replace(/_/g, " ").toUpperCase()}
**Assigned To:** ${row.control.assignedTo ?? "Unassigned"}

The organization needs specific, actionable guidance to ${row.control.status === "non_compliant" ? "achieve compliance with" : "maintain and strengthen"} this control. Include evidence collection requirements and common implementation pitfalls.`,
      },
    ], { maxTokens: 1200 });

    if (result) {
      res.json({ content: result, model: "gpt-4o-mini", generatedAt: new Date().toISOString() });
      return;
    }
  }

  // Template fallback
  const content = `## Compliance Guidance: ${row.control.controlId} — ${row.control.title}

**Framework:** ${row.frameworkName ?? "Unknown"}  
**Current Status:** ${row.control.status.replace(/_/g, " ").toUpperCase()}

### Understanding This Control
${row.control.description ?? `This control (${row.control.controlId}) is part of the ${row.frameworkName ?? "compliance"} framework and addresses critical security governance requirements.`}

### Implementation Steps
1. **Document your current state** — Gather evidence of existing processes, policies, and technical controls.
2. **Identify gaps** — Compare your current state against the control requirements.
3. **Implement remediation** — Address gaps through policy updates, technical controls, or operational changes.
4. **Collect evidence** — Document all controls with screenshots, logs, and policy documents.
5. **Assign ownership** — Designate a control owner for ongoing maintenance.
6. **Schedule reviews** — Set a recurring calendar item for periodic control review.

### Evidence Requirements
- Policy documents and procedures
- Technical configuration screenshots or exports
- Audit logs demonstrating control effectiveness
- Regular review documentation and sign-offs
- Training records (if personnel-related control)

### Recommended Timeline
${row.control.status === "non_compliant" ? "**Priority:** Non-compliant — address within 30-60 days." : "Continue maintaining current compliance and gather ongoing evidence."}`;

  res.json({ content, model: "ctem-template-v1", generatedAt: new Date().toISOString() });
});

router.get("/ai/status", requireAuth, async (_req, res): Promise<void> => {
  res.json({ llmEnabled: isLLMAvailable(), model: isLLMAvailable() ? "gpt-4o-mini" : "template-fallback" });
});

export default router;
