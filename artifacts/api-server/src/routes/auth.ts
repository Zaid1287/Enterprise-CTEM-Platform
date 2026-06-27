import { Router } from "express";
import { eq } from "drizzle-orm";
import { db, tenantsTable, usersTable, sessionsTable } from "@workspace/db";
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
import { logAudit, getClientIp } from "../lib/audit";
import { sendEmail, otpEmailHtml } from "../lib/email";
import crypto from "crypto";
import multer from "multer";
import path from "path";
import fs from "fs";

const router = Router();

// ── Per-email brute-force tracker ─────────────────────────────────────────────
// Tracks failed login attempts per email address so lockout is per-account,
// not per-IP (IP-based locking would lock out all users behind the same proxy).
const MAX_ATTEMPTS = 5;
const LOCKOUT_MS   = 15 * 60 * 1000; // 15 minutes

interface LoginAttemptEntry { count: number; firstAt: number; blockedUntil?: number }
const loginAttempts = new Map<string, LoginAttemptEntry>();

function getAttemptEntry(email: string): LoginAttemptEntry {
  const entry = loginAttempts.get(email);
  if (!entry) return { count: 0, firstAt: Date.now() };
  // Reset window if the lockout has expired
  if (entry.blockedUntil && Date.now() > entry.blockedUntil) {
    loginAttempts.delete(email);
    return { count: 0, firstAt: Date.now() };
  }
  return entry;
}

function recordFailedAttempt(email: string): LoginAttemptEntry {
  const entry = getAttemptEntry(email);
  entry.count += 1;
  if (entry.count >= MAX_ATTEMPTS) {
    entry.blockedUntil = Date.now() + LOCKOUT_MS;
  }
  loginAttempts.set(email, entry);
  return entry;
}

function clearAttempts(email: string): void {
  loginAttempts.delete(email);
}

// Periodically purge expired entries so the Map doesn't grow unbounded
setInterval(() => {
  const now = Date.now();
  for (const [email, entry] of loginAttempts) {
    if (entry.blockedUntil && now > entry.blockedUntil) loginAttempts.delete(email);
    else if (!entry.blockedUntil && now - entry.firstAt > LOCKOUT_MS) loginAttempts.delete(email);
  }
}, 5 * 60 * 1000);

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

function parseBrowser(ua: string): string {
  if (/Edg\//i.test(ua)) return "Edge";
  if (/OPR\//i.test(ua) || /Opera/i.test(ua)) return "Opera";
  if (/Chrome\//i.test(ua)) return "Chrome";
  if (/Firefox\//i.test(ua)) return "Firefox";
  if (/Safari\//i.test(ua)) return "Safari";
  if (/MSIE|Trident/i.test(ua)) return "Internet Explorer";
  return "Unknown Browser";
}

function parseOs(ua: string): string {
  if (/Windows NT 10/i.test(ua)) return "Windows 10/11";
  if (/Windows NT/i.test(ua)) return "Windows";
  if (/Mac OS X/i.test(ua)) return "macOS";
  if (/iPhone/i.test(ua)) return "iOS";
  if (/iPad/i.test(ua)) return "iPadOS";
  if (/Android/i.test(ua)) return "Android";
  if (/Linux/i.test(ua)) return "Linux";
  return "Unknown OS";
}

function parseDevice(ua: string): string {
  if (/iPhone/i.test(ua)) return "iPhone";
  if (/iPad/i.test(ua)) return "iPad";
  if (/Android.*Mobile/i.test(ua)) return "Android Phone";
  if (/Android/i.test(ua)) return "Android Tablet";
  return "Desktop";
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

  const email = parsed.data.email.toLowerCase().trim();

  // ── Per-email lockout check ──
  const attemptEntry = getAttemptEntry(email);
  if (attemptEntry.blockedUntil && Date.now() < attemptEntry.blockedUntil) {
    const remainingMs  = attemptEntry.blockedUntil - Date.now();
    const remainingMin = Math.ceil(remainingMs / 60_000);
    res.status(429).json({
      error: `Account temporarily locked due to too many failed login attempts. Try again in ${remainingMin} minute${remainingMin === 1 ? "" : "s"}.`,
    });
    return;
  }

  const [user] = await db.select().from(usersTable).where(eq(usersTable.email, email));
  if (!user || !user.isActive) {
    recordFailedAttempt(email);
    res.status(401).json({ error: "Invalid credentials" });
    return;
  }

  const valid = await comparePassword(parsed.data.password, user.passwordHash);
  if (!valid) {
    const updated = recordFailedAttempt(email);
    const remaining = MAX_ATTEMPTS - updated.count;
    if (updated.blockedUntil) {
      res.status(429).json({
        error: `Too many failed attempts. Your account is locked for 15 minutes.`,
      });
    } else {
      res.status(401).json({
        error: `Invalid credentials. ${remaining} attempt${remaining === 1 ? "" : "s"} remaining before account lockout.`,
      });
    }
    return;
  }

  // Successful login — clear any failed-attempt counter
  clearAttempts(email);

  // If account requires a password reset, return a specific signal without issuing tokens
  if (user.requiresPasswordReset) {
    res.status(200).json({
      requiresPasswordReset: true,
      userId: user.id,
      email: user.email,
    });
    return;
  }

  const payload = { userId: user.id, tenantId: user.tenantId, email: user.email, role: user.role };
  const accessToken = signAccessToken(payload);
  const refreshToken = signRefreshToken(payload);

  await db.update(usersTable)
    .set({ refreshToken, lastLoginAt: new Date() })
    .where(eq(usersTable.id, user.id));

  const ua = req.headers["user-agent"] ?? "";
  const realIp = getClientIp(req);
  const deviceStr = parseDevice(ua);
  const browserStr = parseBrowser(ua);
  const osStr = parseOs(ua);

  await logAudit(payload, "login", "user", user.id, undefined, realIp, {
    device: deviceStr, browser: browserStr, os: osStr, userAgent: ua,
  });

  // Record session
  const tokenHash = crypto.createHash("sha256").update(accessToken).digest("hex");
  await db.insert(sessionsTable).values({
    userId: user.id,
    tenantId: user.tenantId,
    tokenHash,
    ipAddress: realIp,
    userAgent: ua.substring(0, 500),
    device: deviceStr,
    browser: browserStr,
    os: osStr,
    expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days
  }).onConflictDoNothing();

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

    // Block refresh for accounts that must change their password first
    if (user.requiresPasswordReset) {
      res.status(403).json({ error: "Password reset required", requiresPasswordReset: true });
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
  await db.update(usersTable)
    .set({ passwordHash, requiresPasswordReset: false })
    .where(eq(usersTable.id, user.id));

  res.sendStatus(204);
});

// ── Set Initial Password (for accounts with requiresPasswordReset=true) ───────

router.post("/auth/set-initial-password", async (req, res): Promise<void> => {
  const { userId, currentPassword, newPassword } = req.body ?? {};
  if (!userId || !currentPassword || !newPassword) {
    res.status(400).json({ error: "userId, currentPassword and newPassword are required" }); return;
  }
  if (String(newPassword).length < 8) {
    res.status(400).json({ error: "New password must be at least 8 characters" }); return;
  }

  const [user] = await db.select().from(usersTable).where(eq(usersTable.id, Number(userId)));
  if (!user || !user.isActive) { res.status(404).json({ error: "User not found" }); return; }

  // This endpoint is exclusively for accounts with a forced password reset — reject others
  if (!user.requiresPasswordReset) {
    res.status(403).json({ error: "Use /auth/change-password for regular password changes" }); return;
  }

  const valid = await comparePassword(String(currentPassword), user.passwordHash);
  if (!valid) { res.status(400).json({ error: "Current password is incorrect" }); return; }

  const passwordHash = await hashPassword(String(newPassword));
  await db.update(usersTable)
    .set({ passwordHash, requiresPasswordReset: false, lastLoginAt: new Date() })
    .where(eq(usersTable.id, user.id));

  const payload = { userId: user.id, tenantId: user.tenantId, email: user.email, role: user.role };
  const accessToken = signAccessToken(payload);
  const refreshToken = signRefreshToken(payload);
  await db.update(usersTable).set({ refreshToken }).where(eq(usersTable.id, user.id));

  res.json({ accessToken, refreshToken, user: toUserResponse(user) });
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
  const filename = path.basename(String(req.params.filename));
  const filePath = path.join(AVATARS_DIR, filename);
  if (!fs.existsSync(filePath)) { res.status(404).json({ error: "Not found" }); return; }
  res.sendFile(filePath);
});

// ── Seed compliance frameworks + tools for new tenant (no fake assets/findings) ──

export async function seedNewTenantData(tenantId: number): Promise<void> {
  const { complianceFrameworksTable, securityToolsTable } = await import("@workspace/db");

  // Ensure compliance frameworks exist (shared across all tenants — idempotent)
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

  // Default tools for every tenant — errors propagate to the caller
  await db.insert(securityToolsTable).values([
    { tenantId, name: "subfinder", description: "Subdomain enumeration using passive OSINT sources", githubUrl: "https://github.com/projectdiscovery/subfinder", category: "recon", installCommand: "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest", updateCommand: "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest", runCommand: "subfinder -d {target} -all -json", outputFormat: "json", isActive: true },
    { tenantId, name: "httpx", description: "Fast and multi-purpose HTTP toolkit for probing web servers", githubUrl: "https://github.com/projectdiscovery/httpx", category: "web_recon", installCommand: "go install github.com/projectdiscovery/httpx/cmd/httpx@latest", updateCommand: "go install github.com/projectdiscovery/httpx/cmd/httpx@latest", runCommand: "httpx -u {target} -title -status-code -tech-detect -json", outputFormat: "json", isActive: true },
    { tenantId, name: "naabu", description: "Fast port scanner", githubUrl: "https://github.com/projectdiscovery/naabu", category: "port_scan", installCommand: "go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest", updateCommand: "go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest", runCommand: "naabu -host {target} -top-ports 1000 -json", outputFormat: "json", isActive: true },
    { tenantId, name: "nuclei", description: "Fast and customizable vulnerability scanner", githubUrl: "https://github.com/projectdiscovery/nuclei", category: "vuln_scan", installCommand: "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", updateCommand: "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", runCommand: "nuclei -u {target} -json", outputFormat: "json", isActive: true },
  ]).onConflictDoNothing();
}

export default router;
