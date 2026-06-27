import { eq, and, isNull } from "drizzle-orm";
import { db, tenantsTable } from "@workspace/db";
import type { AuthenticatedRequest } from "./auth";

/**
 * Returns the list of client tenant IDs that a privileged user (admin or super_admin)
 * is allowed to access.
 *
 * - super_admin: all non-platform tenants (isPlatform = false)
 * - admin (non-platform tenant): child tenants where parentTenantId = user.tenantId
 *
 * Returns an empty array if the user has no accessible client tenants.
 * Returns null if the user is not a privileged role (should not call for non-privileged users).
 */
export async function getPrivilegedTenantIds(user: NonNullable<AuthenticatedRequest["user"]>): Promise<number[]> {
  if (user.role === "super_admin") {
    const rows = await db
      .select({ id: tenantsTable.id })
      .from(tenantsTable)
      .where(eq(tenantsTable.isPlatform, false));
    return rows.map(r => r.id);
  }
  if (user.role === "admin") {
    const rows = await db
      .select({ id: tenantsTable.id })
      .from(tenantsTable)
      .where(and(
        eq(tenantsTable.isPlatform, false),
        eq(tenantsTable.parentTenantId, user.tenantId),
      ));
    return rows.map(r => r.id);
  }
  return [];
}

/**
 * Given a set of privileged tenant IDs and an optional ?tenantId query param,
 * returns the effective tenant IDs to filter by.
 *
 * If a specific tenantId is requested and it's within the privileged set, returns [tenantId].
 * Otherwise returns the full privileged set.
 */
export function resolvePrivilegedTenantFilter(ids: number[], qTenantId: number | null): number[] {
  if (qTenantId !== null && ids.includes(qTenantId)) {
    return [qTenantId];
  }
  return ids;
}
