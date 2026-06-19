import { db, accountManagerClientsTable } from "@workspace/db";
import { eq } from "drizzle-orm";

/**
 * Returns the list of client tenant IDs assigned to an account manager user.
 * Returns an empty array if the user has no assigned clients.
 * Used by all route handlers that need AM-scoped data access.
 */
export async function getAmClientTenantIds(amUserId: number): Promise<number[]> {
  const rows = await db
    .select({ clientTenantId: accountManagerClientsTable.clientTenantId })
    .from(accountManagerClientsTable)
    .where(eq(accountManagerClientsTable.accountManagerUserId, amUserId));
  return rows.map(r => r.clientTenantId);
}
