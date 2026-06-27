import { eq, and, inArray as drizzleInArray } from "drizzle-orm";
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
 * If a specific tenantId is requested but NOT in the privileged set, returns [] (no access).
 * If no specific tenantId is requested, returns the full privileged set.
 */
export function resolvePrivilegedTenantFilter(ids: number[], qTenantId: number | null): number[] {
  if (qTenantId !== null) {
    return ids.includes(qTenantId) ? [qTenantId] : [];
  }
  return ids;
}

/**
 * Builds a WHERE clause for a single-record lookup that constrains admin/SA access
 * to accessible client tenant IDs.
 *
 * Usage (for admin/SA detail routes):
 *   const privIds = await getPrivilegedTenantIds(req.user!);
 *   const where = buildRecordFilter(eq(table.id, id), table.tenantId, privIds);
 *   const [row] = await db.select().from(table).where(where);
 *
 * Returns a filter that will yield no results (tenantId = -1) when privIds is empty,
 * ensuring a 404 for admin/SA with no accessible tenants.
 */
export function buildRecordFilter(
  idExpr: ReturnType<typeof eq>,
  tenantIdCol: any,
  privIds: number[],
): ReturnType<typeof and> {
  if (privIds.length === 0) return and(idExpr, eq(tenantIdCol, -1)) as any;
  return and(idExpr, drizzleInArray(tenantIdCol, privIds)) as any;
}
