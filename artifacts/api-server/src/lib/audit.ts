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

/** Parse browser name from User-Agent string */
export function parseBrowser(ua: string): string {
  if (/Edg\//i.test(ua)) return "Edge";
  if (/OPR\//i.test(ua) || /Opera/i.test(ua)) return "Opera";
  if (/Chrome\//i.test(ua)) return "Chrome";
  if (/Firefox\//i.test(ua)) return "Firefox";
  if (/Safari\//i.test(ua)) return "Safari";
  if (/MSIE|Trident/i.test(ua)) return "Internet Explorer";
  return "Unknown Browser";
}

/** Parse OS name from User-Agent string */
export function parseOs(ua: string): string {
  if (/Windows NT 10/i.test(ua)) return "Windows 10/11";
  if (/Windows NT/i.test(ua)) return "Windows";
  if (/Mac OS X/i.test(ua)) return "macOS";
  if (/iPhone/i.test(ua)) return "iOS";
  if (/iPad/i.test(ua)) return "iPadOS";
  if (/Android/i.test(ua)) return "Android";
  if (/Linux/i.test(ua)) return "Linux";
  return "Unknown OS";
}

/** Parse device type from User-Agent string */
export function parseDevice(ua: string): string {
  if (/iPhone/i.test(ua)) return "iPhone";
  if (/iPad/i.test(ua)) return "iPad";
  if (/Android.*Mobile/i.test(ua)) return "Android Phone";
  if (/Android/i.test(ua)) return "Android Tablet";
  return "Desktop";
}

/**
 * Write an audit log entry.
 *
 * `ipOrReq` can be:
 *  - A plain string IP address (legacy — used by auth routes)
 *  - An Express `Request` object — IP address, browser, OS, device, and
 *    user-agent are ALL extracted automatically. This is the preferred form
 *    for every non-auth route.
 *
 * `opts` (explicit browser/os/device/userAgent) is only used when `ipOrReq`
 * is a string; it is ignored when a Request object is passed.
 */
export async function logAudit(
  user: JwtPayload,
  action: string,
  resource: string,
  resourceId?: number,
  details?: string,
  ipOrReq?: string | Request,
  opts?: { device?: string; browser?: string; os?: string; userAgent?: string }
): Promise<void> {
  try {
    let ipAddress: string | undefined;
    let device = opts?.device;
    let browser = opts?.browser;
    let os = opts?.os;
    let userAgent = opts?.userAgent;

    if (typeof ipOrReq === "string") {
      // Legacy: plain IP string passed directly
      ipAddress = ipOrReq || undefined;
    } else if (ipOrReq != null) {
      // Preferred: full Request object — extract everything
      ipAddress = getClientIp(ipOrReq) || undefined;
      const ua = (ipOrReq.headers["user-agent"] as string | undefined) ?? "";
      userAgent = ua.substring(0, 500) || undefined;
      browser = parseBrowser(ua);
      os = parseOs(ua);
      device = parseDevice(ua);
    }

    await db.insert(auditLogsTable).values({
      tenantId: user.tenantId,
      userId: user.userId,
      userEmail: user.email,
      action,
      resource,
      resourceId,
      details,
      ipAddress,
      device,
      browser,
      os,
      userAgent: userAgent?.substring(0, 500),
    });
  } catch {
    // Audit log failures should not break the main flow
  }
}
