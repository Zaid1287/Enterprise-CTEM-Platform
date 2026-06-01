import { Router } from "express";
import { eq } from "drizzle-orm";
import { db, findingsTable, complianceControlsTable, complianceFrameworksTable } from "@workspace/db";
import { requireAuth, type AuthenticatedRequest } from "../lib/auth";

const router = Router();
const MODEL_NAME = "ctem-ai-v1";

function buildFindingExplanation(title: string, cve: string | null, cvss: number | null, severity: string): string {
  return `## Vulnerability Analysis: ${title}

**Severity:** ${severity.toUpperCase()}${cve ? ` | **CVE:** ${cve}` : ""}${cvss ? ` | **CVSS Score:** ${cvss}` : ""}

### What is this vulnerability?
This finding represents a ${severity}-severity security issue${cve ? ` tracked as ${cve}` : ""} in your environment. ${
    severity === "critical" || severity === "high"
      ? "This is a high-priority vulnerability that poses significant risk to your organization and should be remediated immediately."
      : "This vulnerability should be addressed as part of your regular vulnerability management program."
  }

### Why does it matter?
${cvss && cvss >= 9.0 ? "The CVSS score of " + cvss + " indicates a critical vulnerability that can be exploited with minimal user interaction and may lead to full system compromise." :
  cvss && cvss >= 7.0 ? "The CVSS score of " + cvss + " indicates a high-severity vulnerability requiring prompt attention." :
  "This vulnerability presents a medium risk level that should be scheduled for remediation."}

### Business Impact
Exploitation of this vulnerability could lead to unauthorized access to sensitive systems, data breaches, financial losses, and reputational damage. ${
    severity === "critical" ? "Immediate action is required to prevent potential exploitation." : "Schedule remediation within your next maintenance window."
  }

### Attack Vector
This vulnerability can be exploited by attackers with ${cvss && cvss >= 9.0 ? "no" : "limited"} prior access to the affected system, making it a priority for the security team.`;
}

function buildRemediationSteps(title: string, cve: string | null, severity: string) {
  return {
    steps: [
      `Immediately assess the scope of affected systems running the vulnerable component`,
      `Review vendor security advisories${cve ? ` for ${cve}` : ""} and apply available patches`,
      `If no patch is available, implement compensating controls (WAF rules, network segmentation)`,
      `Test the patch in a non-production environment before deploying to production`,
      `Deploy the fix during a maintenance window with rollback plan prepared`,
      `Verify remediation by re-scanning the affected asset`,
      `Update your asset inventory with the new version information`,
      `Document the remediation in your change management system`,
    ],
    priority: severity === "critical" ? "Immediate (within 24 hours)" :
              severity === "high" ? "Urgent (within 7 days)" :
              severity === "medium" ? "Standard (within 30 days)" : "Low (within 90 days)",
    estimatedEffort: severity === "critical" ? "2-4 hours" : "4-8 hours",
    references: [
      cve ? `https://nvd.nist.gov/vuln/detail/${cve}` : "https://cve.mitre.org",
      "https://owasp.org/www-community/vulnerabilities/",
      "https://attack.mitre.org/",
    ].filter(Boolean),
  };
}

router.post("/ai/explain-finding", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const { findingId } = req.body;
  if (!findingId) { res.status(400).json({ error: "findingId is required" }); return; }
  const [finding] = await db.select().from(findingsTable).where(eq(findingsTable.id, findingId));
  if (!finding) { res.status(404).json({ error: "Finding not found" }); return; }

  const content = buildFindingExplanation(finding.title, finding.cve, finding.cvss, finding.severity);
  res.json({ content, model: MODEL_NAME, generatedAt: new Date().toISOString() });
});

router.post("/ai/remediation", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const { findingId } = req.body;
  if (!findingId) { res.status(400).json({ error: "findingId is required" }); return; }
  const [finding] = await db.select().from(findingsTable).where(eq(findingsTable.id, findingId));
  if (!finding) { res.status(404).json({ error: "Finding not found" }); return; }

  const result = buildRemediationSteps(finding.title, finding.cve, finding.severity);
  res.json({ ...result, model: MODEL_NAME });
});

router.post("/ai/executive-summary", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const { tenantId } = req.body;

  const findings = await db.select().from(findingsTable).where(eq(findingsTable.tenantId, req.user!.tenantId));
  const critical = findings.filter(f => f.severity === "critical").length;
  const high = findings.filter(f => f.severity === "high").length;
  const open = findings.filter(f => f.status === "open").length;
  const kev = findings.filter(f => f.isKev).length;

  const content = `## Executive Security Summary

**Report Date:** ${new Date().toLocaleDateString()}
**Classification:** Confidential

### Security Posture Overview
Your organization's security posture shows ${critical > 0 ? "**critical areas requiring immediate attention**" : "manageable risk levels"}. Our continuous monitoring platform has identified ${findings.length} total findings across your asset inventory.

### Key Metrics
- **Total Findings:** ${findings.length}
- **Critical Severity:** ${critical} (${critical > 0 ? "⚠️ Requires immediate action" : "None"})
- **High Severity:** ${high}
- **Open Findings:** ${open}
- **Known Exploited Vulnerabilities (KEV):** ${kev}

### Top Risks
${critical > 0 ? `Your organization has **${critical} critical vulnerabilities** that represent an immediate threat to business operations. These must be prioritized for remediation within 24 hours.` : "No critical vulnerabilities detected in this period."}
${kev > 0 ? `\n**${kev} findings** match CISA's Known Exploited Vulnerabilities catalog, indicating active exploitation in the wild.` : ""}

### Recommended Actions
1. ${critical > 0 ? "Immediately address all critical severity findings" : "Continue monitoring for new vulnerabilities"}
2. Review and update asset inventory for completeness
3. Ensure all compliance controls are on track
4. Schedule regular penetration testing for high-risk assets
5. Review and test incident response procedures

### Trend Analysis
Security monitoring is active across all registered assets. Continuous scanning ensures new vulnerabilities are detected as they emerge.`;

  res.json({ content, model: MODEL_NAME, generatedAt: new Date().toISOString() });
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

  const content = `## Compliance Guidance: ${row.control.controlId} — ${row.control.title}

**Framework:** ${row.frameworkName ?? "Unknown"}
**Current Status:** ${row.control.status.replace("_", " ").toUpperCase()}

### Understanding This Control
${row.control.description ?? `This control (${row.control.controlId}) is part of the ${row.frameworkName ?? "compliance"} framework and addresses important security and governance requirements.`}

### Implementation Guidance
To achieve compliance with this control, your organization should:

1. **Document your current state** — Gather evidence of existing processes, policies, and technical controls that address this requirement.

2. **Identify gaps** — Compare your current state against the control requirements and document any gaps.

3. **Implement remediation** — Address identified gaps through policy updates, technical controls, or operational changes.

4. **Collect evidence** — Document all implemented controls with screenshots, logs, policy documents, and testing results.

5. **Assign ownership** — Designate a control owner responsible for ongoing maintenance and evidence collection.

### Evidence Requirements
- Policy documents and procedures
- Technical configuration screenshots
- Audit logs demonstrating control effectiveness
- Regular review documentation

### Recommended Timeline
${row.control.status === "non_compliant" ? "**Priority:** This control is non-compliant and should be addressed within 30-60 days." : "Continue maintaining current compliance level and gather ongoing evidence."}`;

  res.json({ content, model: MODEL_NAME, generatedAt: new Date().toISOString() });
});

export default router;
