import { Router } from "express";
import { eq } from "drizzle-orm";
import { db, tenantsTable, usersTable } from "@workspace/db";
import { LoginBody, RegisterBody, RefreshTokenBody, ChangePasswordBody } from "@workspace/api-zod";
import {
  hashPassword,
  comparePassword,
  signAccessToken,
  signRefreshToken,
  verifyToken,
  requireAuth,
  type AuthenticatedRequest,
} from "../lib/auth";
import { logAudit } from "../lib/audit";

const router = Router();

function toUserResponse(user: typeof usersTable.$inferSelect) {
  return {
    id: user.id,
    email: user.email,
    firstName: user.firstName,
    lastName: user.lastName,
    role: user.role,
    tenantId: user.tenantId,
    isActive: user.isActive,
    lastLoginAt: user.lastLoginAt?.toISOString() ?? null,
    createdAt: user.createdAt.toISOString(),
  };
}

router.post("/auth/login", async (req, res): Promise<void> => {
  const parsed = LoginBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.message });
    return;
  }

  const [user] = await db.select().from(usersTable).where(eq(usersTable.email, parsed.data.email));
  if (!user || !user.isActive) {
    res.status(401).json({ error: "Invalid credentials" });
    return;
  }

  const valid = await comparePassword(parsed.data.password, user.passwordHash);
  if (!valid) {
    res.status(401).json({ error: "Invalid credentials" });
    return;
  }

  const payload = { userId: user.id, tenantId: user.tenantId, email: user.email, role: user.role };
  const accessToken = signAccessToken(payload);
  const refreshToken = signRefreshToken(payload);

  await db.update(usersTable)
    .set({ refreshToken, lastLoginAt: new Date() })
    .where(eq(usersTable.id, user.id));

  await logAudit(payload, "login", "user", user.id, undefined, req.ip);

  res.json({ accessToken, refreshToken, user: toUserResponse(user) });
});

router.post("/auth/register", async (req, res): Promise<void> => {
  const parsed = RegisterBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.message });
    return;
  }

  const existing = await db.select().from(usersTable).where(eq(usersTable.email, parsed.data.email));
  if (existing.length > 0) {
    res.status(409).json({ error: "Email already in use" });
    return;
  }

  const [tenant] = await db.insert(tenantsTable).values({
    name: parsed.data.tenantName,
    slug: parsed.data.tenantName.toLowerCase().replace(/\s+/g, "-").replace(/[^a-z0-9-]/g, ""),
    plan: "starter",
  }).returning();

  const passwordHash = await hashPassword(parsed.data.password);
  const [user] = await db.insert(usersTable).values({
    tenantId: tenant.id,
    email: parsed.data.email,
    passwordHash,
    firstName: parsed.data.firstName,
    lastName: parsed.data.lastName,
    role: "admin",
  }).returning();

  const payload = { userId: user.id, tenantId: user.tenantId, email: user.email, role: user.role };
  const accessToken = signAccessToken(payload);
  const refreshToken = signRefreshToken(payload);

  await db.update(usersTable).set({ refreshToken }).where(eq(usersTable.id, user.id));

  await seedNewTenantData(tenant.id);

  res.status(201).json({ accessToken, refreshToken, user: toUserResponse(user) });
});

router.post("/auth/refresh", async (req, res): Promise<void> => {
  const parsed = RefreshTokenBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.message });
    return;
  }

  try {
    const payload = verifyToken(parsed.data.refreshToken);
    const [user] = await db.select().from(usersTable)
      .where(eq(usersTable.id, payload.userId));

    if (!user || user.refreshToken !== parsed.data.refreshToken) {
      res.status(401).json({ error: "Invalid refresh token" });
      return;
    }

    const newPayload = { userId: user.id, tenantId: user.tenantId, email: user.email, role: user.role };
    const accessToken = signAccessToken(newPayload);
    const refreshToken = signRefreshToken(newPayload);

    await db.update(usersTable).set({ refreshToken }).where(eq(usersTable.id, user.id));

    res.json({ accessToken, refreshToken, user: toUserResponse(user) });
  } catch {
    res.status(401).json({ error: "Invalid refresh token" });
  }
});

router.post("/auth/logout", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  if (req.user) {
    await db.update(usersTable).set({ refreshToken: null }).where(eq(usersTable.id, req.user.userId));
    await logAudit(req.user, "logout", "user", req.user.userId, undefined, req.ip);
  }
  res.sendStatus(204);
});

router.get("/auth/me", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const [user] = await db.select().from(usersTable).where(eq(usersTable.id, req.user!.userId));
  if (!user) {
    res.status(404).json({ error: "User not found" });
    return;
  }
  res.json(toUserResponse(user));
});

router.post("/auth/change-password", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const parsed = ChangePasswordBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.message });
    return;
  }

  const [user] = await db.select().from(usersTable).where(eq(usersTable.id, req.user!.userId));
  if (!user) {
    res.status(404).json({ error: "User not found" });
    return;
  }

  const valid = await comparePassword(parsed.data.currentPassword, user.passwordHash);
  if (!valid) {
    res.status(400).json({ error: "Current password is incorrect" });
    return;
  }

  const passwordHash = await hashPassword(parsed.data.newPassword);
  await db.update(usersTable).set({ passwordHash }).where(eq(usersTable.id, user.id));

  res.sendStatus(204);
});

// Seed demo data for new tenant on registration
async function seedNewTenantData(tenantId: number): Promise<void> {
  try {
    const { assetsTable, findingsTable, scansTable, alertsTable, riskScoresTable,
      complianceFrameworksTable, complianceControlsTable } = await import("@workspace/db");

    // Seed assets
    const assets = await db.insert(assetsTable).values([
      { tenantId, name: "Main Website", type: "domain", value: "acme-corp.com", verificationStatus: "verified", riskLevel: "medium", tags: ["production", "external"] },
      { tenantId, name: "API Gateway", type: "url", value: "api.acme-corp.com", verificationStatus: "verified", riskLevel: "high", tags: ["production", "external"] },
      { tenantId, name: "Admin Panel", type: "url", value: "admin.acme-corp.com", verificationStatus: "verified", riskLevel: "critical", tags: ["production", "internal"] },
      { tenantId, name: "Dev Server", type: "ip", value: "10.0.1.50", verificationStatus: "verified", riskLevel: "low", tags: ["development", "internal"], ipAddress: "10.0.1.50" },
      { tenantId, name: "Cloud Storage", type: "cloud_asset", value: "acme-prod-storage.s3.amazonaws.com", verificationStatus: "verified", riskLevel: "high", tags: ["production", "cloud"] },
    ]).returning();

    // Seed scans
    const [scan] = await db.insert(scansTable).values([
      { tenantId, name: "Full Attack Surface Scan", type: "full", status: "completed", assetIds: assets.map(a => a.id), findingsCount: 12, startedAt: new Date(Date.now() - 3600000), completedAt: new Date(Date.now() - 1800000) },
    ]).returning();

    // Seed findings
    const findings = await db.insert(findingsTable).values([
      { tenantId, assetId: assets[2].id, scanId: scan.id, title: "CVE-2024-1234: Remote Code Execution in Admin Panel", severity: "critical", status: "open", cve: "CVE-2024-1234", cvss: 9.8, epss: 0.87, cwe: "CWE-78", isKev: true, description: "A critical RCE vulnerability was found in the admin panel authentication module. An unauthenticated attacker can execute arbitrary code.", remediation: "Update to version 2.1.5 or apply the vendor-provided patch immediately.", riskScore: 95 },
      { tenantId, assetId: assets[1].id, scanId: scan.id, title: "CVE-2024-5678: SQL Injection in API Gateway", severity: "high", status: "in_progress", cve: "CVE-2024-5678", cvss: 8.2, epss: 0.42, cwe: "CWE-89", isKev: false, description: "SQL injection vulnerability found in the /api/v1/users endpoint. Attackers can extract sensitive data.", remediation: "Use parameterized queries and input validation.", riskScore: 78 },
      { tenantId, assetId: assets[0].id, scanId: scan.id, title: "Exposed .git directory", severity: "high", status: "open", cve: null, cvss: 7.5, epss: 0.21, cwe: "CWE-200", isKev: false, description: "The .git directory is publicly accessible, leaking source code and commit history.", remediation: "Block access to .git directory via web server configuration.", riskScore: 72 },
      { tenantId, assetId: assets[4].id, scanId: scan.id, title: "Public S3 Bucket with Sensitive Data", severity: "critical", status: "open", cve: null, cvss: 9.1, epss: 0.95, cwe: "CWE-285", isKev: true, description: "S3 bucket is publicly accessible and contains customer PII and financial records.", remediation: "Restrict bucket ACL to private and enable bucket policies to deny public access.", riskScore: 98 },
      { tenantId, assetId: assets[3].id, scanId: scan.id, title: "SSL Certificate Expiring in 14 Days", severity: "medium", status: "open", cve: null, cvss: 5.3, epss: 0.05, cwe: "CWE-295", isKev: false, description: "SSL/TLS certificate will expire in 14 days. After expiry, users will see security warnings.", remediation: "Renew the SSL certificate before expiration.", riskScore: 45 },
      { tenantId, assetId: assets[1].id, scanId: scan.id, title: "CVE-2023-9999: Outdated OpenSSL Version", severity: "medium", status: "mitigated", cve: "CVE-2023-9999", cvss: 5.9, epss: 0.12, cwe: "CWE-327", isKev: false, description: "Server is running OpenSSL 1.1.1 which reached end-of-life.", remediation: "Upgrade to OpenSSL 3.x.", riskScore: 40 },
    ]).returning();

    // Seed risk scores
    await db.insert(riskScoresTable).values([
      { assetId: assets[0].id, score: 62, level: "high", cvssComponent: 30, epssComponent: 20, kevBonus: 0, criticalityBonus: 10, exposureBonus: 2 },
      { assetId: assets[1].id, score: 78, level: "high", cvssComponent: 35, epssComponent: 25, kevBonus: 0, criticalityBonus: 15, exposureBonus: 3 },
      { assetId: assets[2].id, score: 95, level: "critical", cvssComponent: 45, epssComponent: 30, kevBonus: 10, criticalityBonus: 8, exposureBonus: 2 },
      { assetId: assets[3].id, score: 25, level: "low", cvssComponent: 10, epssComponent: 5, kevBonus: 0, criticalityBonus: 8, exposureBonus: 2 },
      { assetId: assets[4].id, score: 98, level: "critical", cvssComponent: 42, epssComponent: 40, kevBonus: 10, criticalityBonus: 4, exposureBonus: 2 },
    ]);

    // Seed alerts
    await db.insert(alertsTable).values([
      { tenantId, title: "Critical RCE Found on Admin Panel", message: "CVE-2024-1234 with CVSS 9.8 and KEV classification detected on admin.acme-corp.com", type: "new_vulnerability", severity: "critical", isRead: false, relatedAssetId: assets[2].id, relatedFindingId: findings[0].id },
      { tenantId, title: "Public S3 Bucket Exposure Detected", message: "Customer data may be publicly accessible via S3 bucket", type: "critical_exposure", severity: "critical", isRead: false, relatedAssetId: assets[4].id },
      { tenantId, title: "SSL Certificate Expiring Soon", message: "SSL certificate for dev server expires in 14 days", type: "ssl_expiry", severity: "medium", isRead: true, relatedAssetId: assets[3].id },
      { tenantId, title: "New Asset Discovered", message: "Passive discovery found new subdomain: staging.acme-corp.com", type: "new_asset", severity: "low", isRead: true },
    ]);

    // Get or create compliance frameworks
    let frameworks = await db.select().from(complianceFrameworksTable);
    if (frameworks.length === 0) {
      frameworks = await db.insert(complianceFrameworksTable).values([
        { name: "ISO 27001", shortName: "ISO27001", version: "2022", description: "Information security management systems standard", totalControls: 93 },
        { name: "SOC 2 Type II", shortName: "SOC2", version: "2017", description: "Service Organization Control 2 framework", totalControls: 64 },
        { name: "PCI DSS", shortName: "PCI-DSS", version: "4.0", description: "Payment Card Industry Data Security Standard", totalControls: 281 },
        { name: "HIPAA", shortName: "HIPAA", version: "2013", description: "Health Insurance Portability and Accountability Act", totalControls: 54 },
        { name: "CIS Controls", shortName: "CIS", version: "v8", description: "Center for Internet Security Critical Security Controls", totalControls: 153 },
      ]).returning();
    }

    // Seed compliance controls
    const iso = frameworks.find(f => f.shortName === "ISO27001")!;
    const soc2 = frameworks.find(f => f.shortName === "SOC2")!;
    const pci = frameworks.find(f => f.shortName === "PCI-DSS")!;

    await db.insert(complianceControlsTable).values([
      { tenantId, frameworkId: iso.id, controlId: "A.5.1", title: "Policies for information security", status: "compliant", evidence: "Information security policy documented and approved by management" },
      { tenantId, frameworkId: iso.id, controlId: "A.8.1", title: "Inventory of information and other associated assets", status: "in_progress", evidence: "Asset inventory in CTEM platform - partially complete" },
      { tenantId, frameworkId: iso.id, controlId: "A.8.8", title: "Management of technical vulnerabilities", status: "non_compliant", evidence: null, assignedTo: "security@acme-corp.com" },
      { tenantId, frameworkId: iso.id, controlId: "A.9.2", title: "User access provisioning", status: "compliant" },
      { tenantId, frameworkId: iso.id, controlId: "A.12.6", title: "Management of technical vulnerabilities", status: "in_progress" },
      { tenantId, frameworkId: soc2.id, controlId: "CC6.1", title: "Logical and physical access controls", status: "compliant" },
      { tenantId, frameworkId: soc2.id, controlId: "CC7.1", title: "Security monitoring", status: "in_progress" },
      { tenantId, frameworkId: soc2.id, controlId: "CC9.1", title: "Risk mitigation activities", status: "non_compliant" },
      { tenantId, frameworkId: pci.id, controlId: "6.3.3", title: "All system components are protected from known vulnerabilities", status: "non_compliant", assignedTo: "devops@acme-corp.com" },
      { tenantId, frameworkId: pci.id, controlId: "11.3.1", title: "External penetration testing", status: "in_progress" },
    ]);

  } catch (err) {
    // Seed failure should not block registration
  }
}

export default router;
