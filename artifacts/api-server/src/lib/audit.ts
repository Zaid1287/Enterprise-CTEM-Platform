import { db } from "@workspace/db";
import { auditLogsTable } from "@workspace/db";
import type { JwtPayload } from "./auth";

export async function logAudit(
  user: JwtPayload,
  action: string,
  resource: string,
  resourceId?: number,
  details?: string,
  ipAddress?: string
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
    });
  } catch {
    // Audit log failures should not break the main flow
  }
}
