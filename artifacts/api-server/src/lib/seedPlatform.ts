import { eq } from "drizzle-orm";
import { db, tenantsTable, usersTable } from "@workspace/db";
import { hashPassword } from "./auth";
import { logger } from "./logger";

export async function seedPlatformOnStartup(): Promise<void> {
  try {
    const [platformTenant] = await db.select().from(tenantsTable)
      .where(eq(tenantsTable.isPlatform, true));

    if (!platformTenant) {
      const [tenant] = await db.insert(tenantsTable).values({
        name: "Platform",
        slug: "platform",
        plan: "enterprise",
        isPlatform: true,
        isActive: true,
      }).returning();

      const passwordHash = await hashPassword("123456789");
      await db.insert(usersTable).values({
        tenantId: tenant.id,
        email: "jes@gmail.com",
        passwordHash,
        firstName: "Super",
        lastName: "Admin",
        role: "super_admin",
        isActive: true,
      });

      logger.info("Platform tenant seeded. Login: jes@gmail.com / 123456789");
    }
  } catch (err) {
    logger.error({ err }, "Platform seed failed");
  }
}
