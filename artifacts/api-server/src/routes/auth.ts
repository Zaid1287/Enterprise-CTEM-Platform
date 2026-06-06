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
import { sendEmail, otpEmailHtml } from "../lib/email";
import crypto from "crypto";
import multer from "multer";
import path from "path";
import fs from "fs";

const router = Router();

const AVATARS_DIR = path.join(process.cwd(), "avatars");
if (!fs.existsSync(AVATARS_DIR)) fs.mkdirSync(AVATARS_DIR, { recursive: true });

const avatarUpload = multer({
  storage: multer.diskStorage({
    destination: (_req, _file, cb) => cb(null, AVATARS_DIR),
    filename: (req, file, cb) => {
      const ext = path.extname(file.originalname).toLowerCase();
      cb(null, `avatar-${(req as AuthenticatedRequest).user!.userId}${ext}`);
    },
  }),
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    cb(null, ["image/png", "image/jpeg", "image/gif", "image/webp"].includes(file.mimetype));
  },
});

function generateOtp(): string {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

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
    avatarUrl: user.avatarUrl ?? null,
    isEmailVerified: user.isEmailVerified,
    twoFactorEnabled: user.twoFactorEnabled,
    createdAt: user.createdAt.toISOString(),
  };
}

// ── Login ─────────────────────────────────────────────────────────────────────

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

  // If 2FA is enabled, send OTP and return partial response
  if (user.twoFactorEnabled) {
    const otp = generateOtp();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 min
    await db.update(usersTable)
      .set({ twoFactorOtp: otp, twoFactorOtpExpiresAt: expiresAt })
      .where(eq(usersTable.id, user.id));
    await sendEmail({
      to: user.email,
      subject: "Your Sentinelware login code",
      html: otpEmailHtml({
        title: "Two-factor authentication",
        otp,
        message: "Enter this code to complete your sign-in.",
        expiresMinutes: 10,
      }),
    });
    res.json({ twoFactorRequired: true, accessToken, refreshToken, user: toUserResponse(user) });
    return;
  }

  res.json({ accessToken, refreshToken, user: toUserResponse(user) });
});

// ── Register ──────────────────────────────────────────────────────────────────

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

// ── Refresh ───────────────────────────────────────────────────────────────────

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

// ── Logout ────────────────────────────────────────────────────────────────────

router.post("/auth/logout", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  if (req.user) {
    await db.update(usersTable).set({ refreshToken: null }).where(eq(usersTable.id, req.user.userId));
    await logAudit(req.user, "logout", "user", req.user.userId, undefined, req.ip);
  }
  res.sendStatus(204);
});

// ── Me ────────────────────────────────────────────────────────────────────────

router.get("/auth/me", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const [user] = await db.select().from(usersTable).where(eq(usersTable.id, req.user!.userId));
  if (!user) {
    res.status(404).json({ error: "User not found" });
    return;
  }
  res.json(toUserResponse(user));
});

// ── Change Password ───────────────────────────────────────────────────────────

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

// ── Forgot Password ───────────────────────────────────────────────────────────

router.post("/auth/forgot-password", async (req, res): Promise<void> => {
  const { email } = req.body;
  if (!email) { res.status(400).json({ error: "Email is required" }); return; }

  const [user] = await db.select().from(usersTable).where(eq(usersTable.email, email));
  // Always return success to avoid email enumeration
  if (!user) { res.json({ message: "If that email exists, a reset code has been sent." }); return; }

  const otp = generateOtp();
  const expiresAt = new Date(Date.now() + 15 * 60 * 1000); // 15 min

  await db.update(usersTable)
    .set({ passwordResetToken: otp, passwordResetExpiresAt: expiresAt })
    .where(eq(usersTable.id, user.id));

  await sendEmail({
    to: user.email,
    subject: "Reset your Sentinelware password",
    html: otpEmailHtml({
      title: "Password reset",
      otp,
      message: "Enter this code to reset your password.",
      expiresMinutes: 15,
    }),
  });

  res.json({ message: "If that email exists, a reset code has been sent." });
});

// ── Reset Password ────────────────────────────────────────────────────────────

router.post("/auth/reset-password", async (req, res): Promise<void> => {
  const { email, otp, newPassword } = req.body;
  if (!email || !otp || !newPassword) {
    res.status(400).json({ error: "email, otp, and newPassword are required" });
    return;
  }
  if (newPassword.length < 8) {
    res.status(400).json({ error: "Password must be at least 8 characters" });
    return;
  }

  const [user] = await db.select().from(usersTable).where(eq(usersTable.email, email));
  if (!user || !user.passwordResetToken || user.passwordResetToken !== otp) {
    res.status(400).json({ error: "Invalid or expired reset code" });
    return;
  }
  if (!user.passwordResetExpiresAt || user.passwordResetExpiresAt < new Date()) {
    res.status(400).json({ error: "Reset code has expired" });
    return;
  }

  const passwordHash = await hashPassword(newPassword);
  await db.update(usersTable)
    .set({ passwordHash, passwordResetToken: null, passwordResetExpiresAt: null })
    .where(eq(usersTable.id, user.id));

  res.json({ message: "Password reset successfully" });
});

// ── 2FA: Enable ───────────────────────────────────────────────────────────────

router.post("/auth/2fa/enable", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const [user] = await db.select().from(usersTable).where(eq(usersTable.id, req.user!.userId));
  if (!user) { res.status(404).json({ error: "User not found" }); return; }

  const otp = generateOtp();
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000);
  await db.update(usersTable)
    .set({ twoFactorOtp: otp, twoFactorOtpExpiresAt: expiresAt })
    .where(eq(usersTable.id, user.id));

  await sendEmail({
    to: user.email,
    subject: "Enable two-factor authentication",
    html: otpEmailHtml({
      title: "Enable 2FA",
      otp,
      message: "Enter this code to enable two-factor authentication on your account.",
      expiresMinutes: 10,
    }),
  });

  res.json({ message: "Verification code sent to your email" });
});

router.post("/auth/2fa/confirm", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const { otp } = req.body;
  if (!otp) { res.status(400).json({ error: "OTP is required" }); return; }

  const [user] = await db.select().from(usersTable).where(eq(usersTable.id, req.user!.userId));
  if (!user || !user.twoFactorOtp || user.twoFactorOtp !== otp) {
    res.status(400).json({ error: "Invalid verification code" });
    return;
  }
  if (!user.twoFactorOtpExpiresAt || user.twoFactorOtpExpiresAt < new Date()) {
    res.status(400).json({ error: "Verification code has expired" });
    return;
  }

  await db.update(usersTable)
    .set({ twoFactorEnabled: true, twoFactorOtp: null, twoFactorOtpExpiresAt: null })
    .where(eq(usersTable.id, user.id));

  res.json({ message: "Two-factor authentication enabled" });
});

// ── 2FA: Verify at login ──────────────────────────────────────────────────────

router.post("/auth/2fa/verify", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const { otp } = req.body;
  if (!otp) { res.status(400).json({ error: "OTP is required" }); return; }

  const [user] = await db.select().from(usersTable).where(eq(usersTable.id, req.user!.userId));
  if (!user || !user.twoFactorOtp || user.twoFactorOtp !== otp) {
    res.status(400).json({ error: "Invalid verification code" });
    return;
  }
  if (!user.twoFactorOtpExpiresAt || user.twoFactorOtpExpiresAt < new Date()) {
    res.status(400).json({ error: "Code has expired. Please sign in again." });
    return;
  }

  await db.update(usersTable)
    .set({ twoFactorOtp: null, twoFactorOtpExpiresAt: null })
    .where(eq(usersTable.id, user.id));

  res.json({ verified: true });
});

// ── 2FA: Disable ──────────────────────────────────────────────────────────────

router.post("/auth/2fa/disable", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const { password } = req.body;
  if (!password) { res.status(400).json({ error: "Password is required to disable 2FA" }); return; }

  const [user] = await db.select().from(usersTable).where(eq(usersTable.id, req.user!.userId));
  if (!user) { res.status(404).json({ error: "User not found" }); return; }

  const valid = await comparePassword(password, user.passwordHash);
  if (!valid) { res.status(400).json({ error: "Incorrect password" }); return; }

  await db.update(usersTable)
    .set({ twoFactorEnabled: false, twoFactorOtp: null, twoFactorOtpExpiresAt: null })
    .where(eq(usersTable.id, user.id));

  res.json({ message: "Two-factor authentication disabled" });
});

// ── Avatar upload ─────────────────────────────────────────────────────────────

router.post("/auth/avatar", requireAuth, avatarUpload.single("avatar"), async (req: AuthenticatedRequest, res): Promise<void> => {
  if (!req.file) { res.status(400).json({ error: "No file uploaded" }); return; }
  const avatarUrl = `/api/auth/avatar/${req.file.filename}`;
  await db.update(usersTable)
    .set({ avatarUrl })
    .where(eq(usersTable.id, req.user!.userId));
  res.json({ avatarUrl });
});

router.get("/auth/avatar/:filename", requireAuth, (req: AuthenticatedRequest, res): void => {
  const filename = path.basename(req.params.filename);
  const filePath = path.join(AVATARS_DIR, filename);
  if (!fs.existsSync(filePath)) { res.status(404).json({ error: "Not found" }); return; }
  res.sendFile(filePath);
});

// ── Seed demo data ─────────────────────────────────────────────────────────────

async function seedNewTenantData(tenantId: number): Promise<void> {
  try {
    const { assetsTable, findingsTable, scansTable, alertsTable, riskScoresTable,
      complianceFrameworksTable, complianceControlsTable } = await import("@workspace/db");

    const assets = await db.insert(assetsTable).values([
      { tenantId, name: "Main Website", type: "domain", value: "acme-corp.com", verificationStatus: "verified", riskLevel: "medium", tags: ["production", "external"] },
      { tenantId, name: "API Gateway", type: "url", value: "api.acme-corp.com", verificationStatus: "verified", riskLevel: "high", tags: ["production", "external"] },
      { tenantId, name: "Admin Panel", type: "url", value: "admin.acme-corp.com", verificationStatus: "verified", riskLevel: "critical", tags: ["production", "internal"] },
      { tenantId, name: "Dev Server", type: "ip", value: "10.0.1.50", verificationStatus: "verified", riskLevel: "low", tags: ["development", "internal"], ipAddress: "10.0.1.50" },
      { tenantId, name: "Cloud Storage", type: "cloud_asset", value: "acme-prod-storage.s3.amazonaws.com", verificationStatus: "verified", riskLevel: "high", tags: ["production", "cloud"] },
    ]).returning();

    const [scan] = await db.insert(scansTable).values([
      { tenantId, name: "Full Attack Surface Scan", type: "full", status: "completed", assetIds: assets.map(a => a.id), findingsCount: 12, startedAt: new Date(Date.now() - 3600000), completedAt: new Date(Date.now() - 1800000) },
    ]).returning();

    const findings = await db.insert(findingsTable).values([
      { tenantId, assetId: assets[2].id, scanId: scan.id, title: "CVE-2024-1234: Remote Code Execution in Admin Panel", severity: "critical", status: "open", cve: "CVE-2024-1234", cvss: 9.8, epss: 0.87, cwe: "CWE-78", isKev: true, description: "A critical RCE vulnerability was found in the admin panel authentication module.", remediation: "Update to version 2.1.5 or apply the vendor-provided patch immediately.", riskScore: 95 },
      { tenantId, assetId: assets[1].id, scanId: scan.id, title: "CVE-2024-5678: SQL Injection in API Gateway", severity: "high", status: "in_progress", cve: "CVE-2024-5678", cvss: 8.2, epss: 0.42, cwe: "CWE-89", isKev: false, description: "SQL injection vulnerability found in the /api/v1/users endpoint.", remediation: "Use parameterized queries and input validation.", riskScore: 78 },
      { tenantId, assetId: assets[0].id, scanId: scan.id, title: "Exposed .git directory", severity: "high", status: "open", cve: null, cvss: 7.5, epss: 0.21, cwe: "CWE-200", isKev: false, description: "The .git directory is publicly accessible.", remediation: "Block access to .git directory via web server configuration.", riskScore: 72 },
      { tenantId, assetId: assets[4].id, scanId: scan.id, title: "Public S3 Bucket with Sensitive Data", severity: "critical", status: "open", cve: null, cvss: 9.1, epss: 0.95, cwe: "CWE-285", isKev: true, description: "S3 bucket is publicly accessible and contains customer PII.", remediation: "Restrict bucket ACL to private.", riskScore: 98 },
      { tenantId, assetId: assets[3].id, scanId: scan.id, title: "SSL Certificate Expiring in 14 Days", severity: "medium", status: "open", cve: null, cvss: 5.3, epss: 0.05, cwe: "CWE-295", isKev: false, description: "SSL/TLS certificate will expire in 14 days.", remediation: "Renew the SSL certificate before expiration.", riskScore: 45 },
      { tenantId, assetId: assets[1].id, scanId: scan.id, title: "CVE-2023-9999: Outdated OpenSSL Version", severity: "medium", status: "mitigated", cve: "CVE-2023-9999", cvss: 5.9, epss: 0.12, cwe: "CWE-327", isKev: false, description: "Server is running OpenSSL 1.1.1 which reached end-of-life.", remediation: "Upgrade to OpenSSL 3.x.", riskScore: 40 },
    ]).returning();

    await db.insert(riskScoresTable).values([
      { assetId: assets[0].id, score: 62, level: "high", cvssComponent: 30, epssComponent: 20, kevBonus: 0, criticalityBonus: 10, exposureBonus: 2 },
      { assetId: assets[1].id, score: 78, level: "high", cvssComponent: 35, epssComponent: 25, kevBonus: 0, criticalityBonus: 15, exposureBonus: 3 },
      { assetId: assets[2].id, score: 95, level: "critical", cvssComponent: 45, epssComponent: 30, kevBonus: 10, criticalityBonus: 8, exposureBonus: 2 },
      { assetId: assets[3].id, score: 25, level: "low", cvssComponent: 10, epssComponent: 5, kevBonus: 0, criticalityBonus: 8, exposureBonus: 2 },
      { assetId: assets[4].id, score: 98, level: "critical", cvssComponent: 42, epssComponent: 40, kevBonus: 10, criticalityBonus: 4, exposureBonus: 2 },
    ]);

    await db.insert(alertsTable).values([
      { tenantId, title: "Critical RCE Found on Admin Panel", message: "CVE-2024-1234 with CVSS 9.8 and KEV classification detected", type: "new_vulnerability", severity: "critical", isRead: false, relatedAssetId: assets[2].id, relatedFindingId: findings[0].id },
      { tenantId, title: "Public S3 Bucket Exposure Detected", message: "Customer data may be publicly accessible via S3 bucket", type: "critical_exposure", severity: "critical", isRead: false, relatedAssetId: assets[4].id },
      { tenantId, title: "SSL Certificate Expiring Soon", message: "SSL certificate for dev server expires in 14 days", type: "ssl_expiry", severity: "medium", isRead: true, relatedAssetId: assets[3].id },
      { tenantId, title: "New Asset Discovered", message: "Passive discovery found new subdomain: staging.acme-corp.com", type: "new_asset", severity: "low", isRead: true },
    ]);

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

    const { securityToolsTable } = await import("@workspace/db");
    await db.insert(securityToolsTable).values([
      { tenantId, name: "subfinder", description: "Subdomain enumeration using passive OSINT sources", githubUrl: "https://github.com/projectdiscovery/subfinder", category: "recon", installCommand: "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest", updateCommand: "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest", runCommand: "subfinder -d {target} -all -json", outputFormat: "json", isActive: true },
      { tenantId, name: "httpx", description: "Fast and multi-purpose HTTP toolkit for probing web servers", githubUrl: "https://github.com/projectdiscovery/httpx", category: "web_recon", installCommand: "go install github.com/projectdiscovery/httpx/cmd/httpx@latest", updateCommand: "go install github.com/projectdiscovery/httpx/cmd/httpx@latest", runCommand: "httpx -u {target} -title -status-code -tech-detect -json", outputFormat: "json", isActive: true },
      { tenantId, name: "naabu", description: "Fast port scanner", githubUrl: "https://github.com/projectdiscovery/naabu", category: "port_scan", installCommand: "go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest", updateCommand: "go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest", runCommand: "naabu -host {target} -top-ports 1000 -json", outputFormat: "json", isActive: true },
      { tenantId, name: "nuclei", description: "Fast and customizable vulnerability scanner", githubUrl: "https://github.com/projectdiscovery/nuclei", category: "vuln_scan", installCommand: "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", updateCommand: "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", runCommand: "nuclei -u {target} -json", outputFormat: "json", isActive: true },
    ]);

  } catch (_err) {
    // Seed failure should not block registration
  }
}

export default router;
