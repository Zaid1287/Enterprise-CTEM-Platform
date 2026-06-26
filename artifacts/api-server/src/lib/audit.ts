import { db } from "@workspace/db";
import { auditLogsTable } from "@workspace/db";
import type { JwtPayload } from "./auth";
import type { Request } from "express";

/** Extract the real client IP — prefers X-Forwarded-For over req.ip */
export function getClientIp(req: Request): string {
  const xff = req.headers["x-forwarded-for"];
  if (xff) {
    const first = (Array.isArray(xff) ? xff[0] : xff).split(",")[0].trim();
    if (first && first !== "unknown" && first !== "::1" && first !== "127.0.0.1") {
      return first.replace(/^::ffff:/, "");
    }
  }
  const raw = req.ip ?? (req.socket?.remoteAddress ?? "");
  return raw.replace(/^::ffff:/, "");
}

export async function logAudit(
  user: JwtPayload,
  action: string,
  resource: string,
  resourceId?: number,
  details?: string,
  ipAddress?: string,
  opts?: { device?: string; browser?: string; os?: string; userAgent?: string }
): Promise<void> {
  try {
    await db.insert(auditLogsTable).values({
      tenantId: user.tenantId,
      userId: user.userId,
      userEmail: user.email,
      action,
      resource,
      resourceId,
      details,
      ipAddress,
      device: opts?.device,
      browser: opts?.browser,
      os: opts?.os,
      userAgent: opts?.userAgent?.substring(0, 500),
    });
  } catch {
    // Audit log failures should not break the main flow
  }
}
