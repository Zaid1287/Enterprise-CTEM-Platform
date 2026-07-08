/**
 * Integration test: tenant creation and deletion lifecycle via real HTTP endpoints.
 *
 * Uses the real Express app (no DB mocks) to exercise:
 *   POST /api/tenants  — creates tenant + admin user + seeds data
 *   DELETE /api/tenants/:id  — cascade-deletes all tenant data
 *
 * Verifies:
 *   1. POST /tenants returns admin credentials (temporaryPassword, userId, email)
 *   2. Seed data (compliance frameworks, security tools, orchestrator config) created
 *   3. DELETE /tenants/:id responds 204 and leaves zero orphaned rows
 *   4. Tables without tenantId (scan_jobs, finding_comments) checked via captured IDs
 *
 * Requires DATABASE_URL — test is skipped when absent.
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import request from "supertest";
import { eq, inArray } from "drizzle-orm";

const SKIP = !process.env.DATABASE_URL;

// The rate limiter skips requests when NODE_ENV === "test"
process.env.NODE_ENV = "test";

describe.skipIf(SKIP)("tenant lifecycle — full API end-to-end", () => {
  // IDs captured during test setup and used across test assertions
  let accessToken = "";
  let createdTenantId = 0;
  let adminUserId = 0;
  let adminTempPassword = "";

  // Platform tenant / super_admin created purely for test infrastructure
  let platformTenantId = 0;
  let saUserId = 0;

  // Child record IDs to verify non-tenantId tables directly after deletion
  let capturedScanId = 0;
  let capturedFindingId = 0;

  beforeAll(async () => {
    const ws = await import("@workspace/db");
    const { hashPassword } = await import("../../lib/auth");

    // 1. Create a platform tenant + super_admin for the test caller
    const slug = `test-platform-${Date.now()}`;
    const [pt] = await ws.db
      .insert(ws.tenantsTable)
      .values({ name: "Test Platform Tenant", slug, plan: "enterprise", isPlatform: true })
      .returning();
    platformTenantId = pt.id;

    const ph = await hashPassword("SuperAdmin1!");
    const [sa] = await ws.db
      .insert(ws.usersTable)
      .values({
        tenantId: platformTenantId,
        email: `sa-${Date.now()}@lifecycle.test`,
        passwordHash: ph,
        firstName: "Test",
        lastName: "SuperAdmin",
        role: "super_admin",
        requiresPasswordReset: false,
      })
      .returning();
    saUserId = sa.id;

    // 2. Log in via the real API to get a JWT
    const app = (await import("../../app")).default;
    const loginRes = await request(app)
      .post("/api/auth/login")
      .send({ email: sa.email, password: "SuperAdmin1!" });
    expect(loginRes.status, `Login failed: ${JSON.stringify(loginRes.body)}`).toBe(200);
    accessToken = loginRes.body.accessToken;
  }, 60_000);

  afterAll(async () => {
    if (!platformTenantId) return;
    try {
      const ws = await import("@workspace/db");
      const { cascadeDeleteTenant } = await import("../tenants");
      // Clean up the test client tenant if tests failed partway through
      if (createdTenantId) {
        await cascadeDeleteTenant(createdTenantId);
        await ws.db.delete(ws.tenantsTable).where(eq(ws.tenantsTable.id, createdTenantId));
      }
      // Clean up the platform tenant used by the super_admin test caller
      await cascadeDeleteTenant(platformTenantId);
      await ws.db.delete(ws.tenantsTable).where(eq(ws.tenantsTable.id, platformTenantId));
    } catch {
      // best-effort cleanup
    }
  }, 60_000);

  // ── Phase 1: POST /api/tenants — tenant creation + credential return ─────────

  it("POST /api/tenants returns 201 with tenant and admin credentials", async () => {
    const app = (await import("../../app")).default;
    const res = await request(app)
      .post("/api/tenants")
      .set("Authorization", `Bearer ${accessToken}`)
      .send({
        name: `Lifecycle Client ${Date.now()}`,
        slug: `lifecycle-client-${Date.now()}`,
        plan: "free",
        adminFirstName: "Client",
        adminLastName: "Admin",
        adminEmail: `client-admin-${Date.now()}@lifecycle.test`,
      });

    expect(res.status, `POST /tenants failed: ${JSON.stringify(res.body)}`).toBe(201);

    // Assert tenant fields
    expect(res.body.id).toBeTypeOf("number");
    expect(res.body.isPlatform).toBe(false);

    // Assert admin credentials are present
    expect(res.body.adminUser).toBeDefined();
    expect(res.body.adminUser.id).toBeTypeOf("number");
    expect(res.body.adminUser.email).toContain("@lifecycle.test");
    expect(res.body.adminUser.temporaryPassword).toBeTypeOf("string");
    expect(res.body.adminUser.temporaryPassword.length).toBeGreaterThanOrEqual(10);
    expect(res.body.adminUser.note).toContain("new password");

    createdTenantId = res.body.id;
    adminUserId = res.body.adminUser.id;
    adminTempPassword = res.body.adminUser.temporaryPassword;

    expect(createdTenantId).toBeGreaterThan(0);
  }, 30_000);

  // ── Phase 2: verify seed data under the new tenant ──────────────────────────

  it("seeds security tools for new tenant", async () => {
    const ws = await import("@workspace/db");
    const tools = await ws.db
      .select()
      .from(ws.securityToolsTable)
      .where(eq(ws.securityToolsTable.tenantId, createdTenantId));
    expect(tools.length).toBeGreaterThanOrEqual(4);
    const names = tools.map((t) => t.name);
    expect(names).toContain("subfinder");
    expect(names).toContain("nuclei");
  });

  it("seeds compliance frameworks (shared global records)", async () => {
    const ws = await import("@workspace/db");
    const frameworks = await ws.db.select().from(ws.complianceFrameworksTable);
    expect(frameworks.length).toBeGreaterThanOrEqual(5);
    const shortNames = frameworks.map((f) => f.shortName);
    expect(shortNames).toContain("ISO27001");
    expect(shortNames).toContain("SOC2");
    expect(shortNames).toContain("PCI-DSS");
  });

  it("seeds orchestrator config for new tenant", async () => {
    const { db, orchestratorConfigTable } = await import("@workspace/db");
    const rows = await db
      .select()
      .from(orchestratorConfigTable)
      .where(eq(orchestratorConfigTable.tenantId, createdTenantId));
    expect(rows.length).toBeGreaterThanOrEqual(10);
    const keys = rows.map((r) => r.key);
    expect(keys).toContain("enabled");
    expect(keys).toContain("max_concurrent_requests");
  });

  it("seeds AI mapper module assignment for new tenant", async () => {
    const ws = await import("@workspace/db");
    const rows = await ws.db
      .select()
      .from(ws.aiMapperModuleAssignmentsTable)
      .where(eq(ws.aiMapperModuleAssignmentsTable.tenantId, createdTenantId));
    expect(rows.length).toBe(1);
  });

  // ── Phase 3: populate representative child records ───────────────────────────

  it("can create representative child records under the new tenant", async () => {
    const ws = await import("@workspace/db");

    const [asset] = await ws.db
      .insert(ws.assetsTable)
      .values({
        tenantId: createdTenantId,
        name: "test-asset",
        type: "domain",
        value: `lifecycle-test-${Date.now()}.example.com`,
        verificationStatus: "unverified",
        riskLevel: "info",
        businessImpact: 5,
      })
      .returning();

    const [group] = await ws.db
      .insert(ws.assetGroupsTable)
      .values({ tenantId: createdTenantId, name: "test-group" })
      .returning();
    await ws.db.insert(ws.assetGroupMembersTable).values({ groupId: group.id, assetId: asset.id });

    const [scan] = await ws.db
      .insert(ws.scansTable)
      .values({
        tenantId: createdTenantId,
        name: "lifecycle-test-scan",
        assetIds: [asset.id],
        status: "completed",
        type: "full",
      })
      .returning();
    capturedScanId = scan.id;

    // scan_jobs has no tenantId — captured via scanId
    await ws.db.insert(ws.scanJobsTable).values({
      scanId: scan.id,
      assetId: asset.id,
      status: "completed",
    });

    const [finding] = await ws.db
      .insert(ws.findingsTable)
      .values({
        tenantId: createdTenantId,
        assetId: asset.id,
        scanId: scan.id,
        title: "Test Finding",
        severity: "high",
        status: "open",
        description: "Integration test finding",
      })
      .returning();
    capturedFindingId = finding.id;

    // finding_comments has no tenantId — captured via findingId
    await ws.db.insert(ws.findingCommentsTable).values({
      findingId: finding.id,
      userId: adminUserId,
      content: "test comment",
    });

    await ws.db.insert(ws.alertsTable).values({
      tenantId: createdTenantId,
      title: "Test Alert",
      severity: "high",
      type: "new_finding",
    });

    const { scanSuppressionsTable } = ws;
    await ws.db.insert(scanSuppressionsTable).values({
      tenantId: createdTenantId,
      matchType: "cve_id",
      pattern: "CVE-0000-00000",
      note: "integration test suppression",
    });

    expect(capturedScanId).toBeGreaterThan(0);
    expect(capturedFindingId).toBeGreaterThan(0);
  });

  // ── Phase 4: DELETE /api/tenants/:id — cascade delete via real API ───────────

  it("DELETE /api/tenants/:id returns 204", async () => {
    expect(createdTenantId).toBeGreaterThan(0);
    const app = (await import("../../app")).default;
    const res = await request(app)
      .delete(`/api/tenants/${createdTenantId}`)
      .set("Authorization", `Bearer ${accessToken}`);
    expect(res.status, `DELETE /tenants failed: ${JSON.stringify(res.body)}`).toBe(204);
  }, 30_000);

  // ── Phase 5: orphan checks — all tenant-scoped tables ───────────────────────

  it("all tenant-scoped tables are empty after DELETE", async () => {
    const ws = await import("@workspace/db");
    const { orchestratorConfigTable, scanSuppressionsTable } = ws;

    const orphaned: string[] = [];
    async function assertEmpty(label: string, rows: Promise<unknown[]>) {
      const result = await rows;
      if (result.length > 0) orphaned.push(`${label}=${result.length}`);
    }

    await assertEmpty("users",
      ws.db.select().from(ws.usersTable).where(eq(ws.usersTable.tenantId, createdTenantId)));
    await assertEmpty("assets",
      ws.db.select().from(ws.assetsTable).where(eq(ws.assetsTable.tenantId, createdTenantId)));
    await assertEmpty("asset_groups",
      ws.db.select().from(ws.assetGroupsTable).where(eq(ws.assetGroupsTable.tenantId, createdTenantId)));
    await assertEmpty("scans",
      ws.db.select().from(ws.scansTable).where(eq(ws.scansTable.tenantId, createdTenantId)));
    await assertEmpty("findings",
      ws.db.select().from(ws.findingsTable).where(eq(ws.findingsTable.tenantId, createdTenantId)));
    await assertEmpty("alerts",
      ws.db.select().from(ws.alertsTable).where(eq(ws.alertsTable.tenantId, createdTenantId)));
    await assertEmpty("alert_rules",
      ws.db.select().from(ws.alertRulesTable).where(eq(ws.alertRulesTable.tenantId, createdTenantId)));
    await assertEmpty("compliance_controls",
      ws.db.select().from(ws.complianceControlsTable).where(eq(ws.complianceControlsTable.tenantId, createdTenantId)));
    await assertEmpty("reports",
      ws.db.select().from(ws.reportsTable).where(eq(ws.reportsTable.tenantId, createdTenantId)));
    await assertEmpty("security_tools",
      ws.db.select().from(ws.securityToolsTable).where(eq(ws.securityToolsTable.tenantId, createdTenantId)));
    await assertEmpty("tool_pipeline_steps",
      ws.db.select().from(ws.toolPipelineStepsTable).where(eq(ws.toolPipelineStepsTable.tenantId, createdTenantId)));
    await assertEmpty("tool_runs",
      ws.db.select().from(ws.toolRunsTable).where(eq(ws.toolRunsTable.tenantId, createdTenantId)));
    await assertEmpty("invitations",
      ws.db.select().from(ws.invitationsTable).where(eq(ws.invitationsTable.tenantId, createdTenantId)));
    await assertEmpty("scan_schedules",
      ws.db.select().from(ws.scanSchedulesTable).where(eq(ws.scanSchedulesTable.tenantId, createdTenantId)));
    await assertEmpty("scan_asset_results",
      ws.db.select().from(ws.scanAssetResultsTable).where(eq(ws.scanAssetResultsTable.tenantId, createdTenantId)));
    await assertEmpty("discovery_results",
      ws.db.select().from(ws.discoveryResultsTable).where(eq(ws.discoveryResultsTable.tenantId, createdTenantId)));
    await assertEmpty("brand_threat_scans",
      ws.db.select().from(ws.brandThreatScansTable).where(eq(ws.brandThreatScansTable.tenantId, createdTenantId)));
    await assertEmpty("brand_watchlist",
      ws.db.select().from(ws.brandWatchlistItemsTable).where(eq(ws.brandWatchlistItemsTable.tenantId, createdTenantId)));
    await assertEmpty("takedowns",
      ws.db.select().from(ws.takedownRequestsTable).where(eq(ws.takedownRequestsTable.tenantId, createdTenantId)));
    await assertEmpty("audit_logs",
      ws.db.select().from(ws.auditLogsTable).where(eq(ws.auditLogsTable.tenantId, createdTenantId)));
    await assertEmpty("orchestrator_config",
      ws.db.select().from(orchestratorConfigTable).where(eq(orchestratorConfigTable.tenantId, createdTenantId)));
    await assertEmpty("scan_suppressions",
      ws.db.select().from(scanSuppressionsTable).where(eq(scanSuppressionsTable.tenantId, createdTenantId)));
    await assertEmpty("ai_mapper_assignments",
      ws.db.select().from(ws.aiMapperModuleAssignmentsTable).where(eq(ws.aiMapperModuleAssignmentsTable.tenantId, createdTenantId)));

    expect(
      orphaned,
      `Orphaned rows after DELETE /tenants: ${orphaned.join(", ")}`,
    ).toHaveLength(0);
  });

  it("scan_jobs are gone (direct check via captured scanId — no tenantId column)", async () => {
    expect(capturedScanId).toBeGreaterThan(0);
    const { db, scanJobsTable } = await import("@workspace/db");
    const jobs = await db
      .select()
      .from(scanJobsTable)
      .where(eq(scanJobsTable.scanId, capturedScanId));
    expect(jobs, "scan_jobs orphaned after tenant delete").toHaveLength(0);
  });

  it("finding_comments are gone (direct check via captured findingId — no tenantId column)", async () => {
    expect(capturedFindingId).toBeGreaterThan(0);
    const { db, findingCommentsTable } = await import("@workspace/db");
    const comments = await db
      .select()
      .from(findingCommentsTable)
      .where(eq(findingCommentsTable.findingId, capturedFindingId));
    expect(comments, "finding_comments orphaned after tenant delete").toHaveLength(0);
  });

  it("asset_group_members are gone (asset groups deleted, so no members can remain)", async () => {
    const { db, assetGroupsTable, assetGroupMembersTable } = await import("@workspace/db");
    const groups = await db
      .select({ id: assetGroupsTable.id })
      .from(assetGroupsTable)
      .where(eq(assetGroupsTable.tenantId, createdTenantId));
    expect(groups, "asset_groups orphaned after tenant delete").toHaveLength(0);

    if (groups.length > 0) {
      const members = await db
        .select()
        .from(assetGroupMembersTable)
        .where(inArray(assetGroupMembersTable.groupId, groups.map((g) => g.id)));
      expect(members, "asset_group_members orphaned after tenant delete").toHaveLength(0);
    }
  });

  it("tenant row itself is deleted by the route (not by cascadeDeleteTenant)", async () => {
    const { db, tenantsTable } = await import("@workspace/db");
    const rows = await db
      .select()
      .from(tenantsTable)
      .where(eq(tenantsTable.id, createdTenantId));
    expect(rows, "tenant row should be gone after DELETE /tenants/:id").toHaveLength(0);
    createdTenantId = 0; // prevent afterAll from trying to re-delete
  });
});
