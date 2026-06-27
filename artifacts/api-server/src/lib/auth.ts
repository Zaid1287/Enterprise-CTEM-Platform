import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import type { Request, Response, NextFunction } from "express";
import { db, usersTable } from "@workspace/db";
import { eq } from "drizzle-orm";

const JWT_SECRET = process.env.SESSION_SECRET ?? "ctem-dev-secret-change-in-production";
const ACCESS_TOKEN_EXPIRY = "8h";
const REFRESH_TOKEN_EXPIRY = "7d";

export interface JwtPayload {
  userId: number;
  tenantId: number;
  email: string;
  role: string;
}

export function signAccessToken(payload: JwtPayload): string {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: ACCESS_TOKEN_EXPIRY });
}

export function signRefreshToken(payload: JwtPayload): string {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: REFRESH_TOKEN_EXPIRY });
}

export function verifyToken(token: string): JwtPayload {
  return jwt.verify(token, JWT_SECRET) as JwtPayload;
}

export async function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password, 12);
}

export async function comparePassword(password: string, hash: string): Promise<boolean> {
  return bcrypt.compare(password, hash);
}

export interface AuthenticatedRequest extends Request {
  user?: JwtPayload;
}

export async function requireAuth(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }
  const token = authHeader.slice(7);
  try {
    const payload = verifyToken(token);

    // Enforce requiresPasswordReset: look up the live flag from the DB so
    // already-issued access tokens cannot be used to bypass a forced reset.
    const [user] = await db
      .select({ requiresPasswordReset: usersTable.requiresPasswordReset, isActive: usersTable.isActive })
      .from(usersTable)
      .where(eq(usersTable.id, payload.userId));

    if (!user || !user.isActive) {
      res.status(401).json({ error: "Account not found or deactivated" });
      return;
    }

    if (user.requiresPasswordReset) {
      res.status(403).json({ error: "Password reset required", requiresPasswordReset: true });
      return;
    }

    req.user = payload;
    next();
  } catch {
    res.status(401).json({ error: "Invalid or expired token" });
  }
}

export function requireRole(...roles: string[]) {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
    if (!req.user || !roles.includes(req.user.role)) {
      res.status(403).json({ error: "Forbidden" });
      return;
    }
    next();
  };
}

const EXTERNAL_ROLES = new Set(["vendor", "employee", "third_party"]);

/**
 * Blocks external members (vendor/employee/third_party) from the entire router.
 * Apply as `router.use(denyExternalMembers)` as the first middleware on any
 * router that external members should have no access to.
 *
 * This middleware runs BEFORE requireAuth on the same router, so it must
 * decode the Bearer token itself rather than relying on req.user being set.
 * It only blocks authenticated external-role requests; unauthenticated
 * requests fall through to requireAuth which will return 401 as normal.
 */
export function denyExternalMembers(req: AuthenticatedRequest, res: Response, next: NextFunction): void {
  // If requireAuth already ran (e.g. combined use), use the cached payload
  if (req.user) {
    if (EXTERNAL_ROLES.has(req.user.role)) {
      res.status(403).json({ error: "Forbidden" });
      return;
    }
    next();
    return;
  }

  // Decode the token without a DB round-trip (signature still verified)
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith("Bearer ")) {
    try {
      const payload = verifyToken(authHeader.slice(7));
      if (EXTERNAL_ROLES.has(payload.role)) {
        res.status(403).json({ error: "Forbidden" });
        return;
      }
    } catch {
      // Invalid/expired token — let requireAuth handle the 401
    }
  }
  next();
}
