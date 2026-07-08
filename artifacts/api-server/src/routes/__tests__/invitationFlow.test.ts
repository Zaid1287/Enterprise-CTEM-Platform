/**
 * Integration test: full invite → accept → login flow.
 *
 * Covers:
 *   1. GET  /api/auth/invitation-info  — pre-fills form data without auth
 *   2. POST /api/auth/accept-invitation — creates user, maps assets, issues tokens
 *   3. GET  /api/assets  (as vendor)    — only granted assets returned (scoped)
 *   4. GET  /api/findings (as vendor)   — only findings for granted assets returned
 *   5. GET  /api/assets/:ungrantedId    — returns 404 for ungGranted asset
 *   6. Error paths: invalid token, expired token, already-used token, duplicate email,
 *      short password, missing asset IDs for external role
 *
 * Requires DATABASE_URL — skipped when absent.
 * Rate limiter is disabled when NODE_ENV === "test".
 *
 * Implementation notes:
 * - POST /api/tenants creates a "client"-role user, which lacks INVITE_AUTHORITY to
 *   send invitations. A separate admin user is inserted directly into the client tenant.
 * - The vendor access token is captured directly from the accept-invitation response
 *   so tests do not need to re-login (avoids requiresPasswordReset edge cases).
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import request from "supertest";
import { eq } from "drizzle-orm";
import crypto from "crypto";

const SKIP = !process.env.DATABASE_URL;
process.env.NODE_ENV = "test";

describe.skipIf(SKIP)("invite → accept → login flow — end-to-end", () => {
  // Platform tenant / super_admin
  let platformTenantId = 0;

  // Client tenant + admin
  let clientTenantId = 0;
  let clientAdminUserId = 0;
  let clientAdminToken = "";

  // Two assets: only asset A is granted to the vendor
  let grantedAssetId = 0;
  let ungrantedAssetId = 0;

  // Invitation token used across sequential test steps
  let validToken = "";

  // Vendor — captured after accept-invitation
  let vendorUserId = 0;
  let vendorAccessToken = "";  // taken directly from accept-invitation response

  // ── Setup ─────────────────────────────────────────────────────────────────

  beforeAll(async () => {
    const ws = await import("@workspace/db");
    const { hashPassword } = await import("../../lib/auth");

    const ts = Date.now();

    // 1. Platform tenant + super_admin (needed to create a client tenant via API)
    const [pt] = await ws.db
      .insert(ws.tenantsTable)
      .values({ name: `InvTest Platform ${ts}`, slug: `invtest-platform-${ts}`, plan: "enterprise", isPlatform: true })
      .returning();
    platformTenantId = pt.id;

    const saHash = await hashPassword("SuperAdmin1!");
    const [sa] = await ws.db
      .insert(ws.usersTable)
      .values({
        tenantId: platformTenantId,
        email: `sa-${ts}@invtest.local`,
        passwordHash: saHash,
        firstName: "SA",
        lastName: "Test",
        role: "super_admin",
        requiresPasswordReset: false,
      })
      .returning();

    const app = (await import("../../app")).default;
    const saLogin = await request(app)
      .post("/api/auth/login")
      .send({ email: sa.email, password: "SuperAdmin1!" });
    expect(saLogin.status, `SA login failed: ${JSON.stringify(saLogin.body)}`).toBe(200);
    const saAccessToken = saLogin.body.accessToken;

    // 2. Create client tenant via API (this creates a "client"-role tenant user — NOT an admin)
    const tenantRes = await request(app)
      .post("/api/tenants")
      .set("Authorization", `Bearer ${saAccessToken}`)
      .send({
        name: `InvTest Client ${ts}`,
        slug: `invtest-client-${ts}`,
        plan: "free",
        adminFirstName: "Client",
        adminLastName: "Admin",
        adminEmail: `client-admin-${ts}@invtest.local`,
      });
    expect(tenantRes.status, `Create tenant failed: ${JSON.stringify(tenantRes.body)}`).toBe(201);
    clientTenantId = tenantRes.body.id;

    // POST /api/tenants creates a "client"-role user (INVITE_AUTHORITY["client"] = []).
    // Insert a separate true admin user that can send invitations.
    const adminHash = await hashPassword("AdminPass1!");
    const [adminUser] = await ws.db
      .insert(ws.usersTable)
      .values({
        tenantId: clientTenantId,
        email: `client-truadmin-${ts}@invtest.local`,
        passwordHash: adminHash,
        firstName: "True",
        lastName: "Admin",
        role: "admin",
        requiresPasswordReset: false,
      })
      .returning();
    clientAdminUserId = adminUser.id;

    const adminLogin = await request(app)
      .post("/api/auth/login")
      .send({ email: adminUser.email, password: "AdminPass1!" });
    expect(adminLogin.status, `Client admin login failed: ${JSON.stringify(adminLogin.body)}`).toBe(200);
    clientAdminToken = adminLogin.body.accessToken;
    expect(clientAdminToken, "client admin token missing").toBeTruthy();

    // 3. Create two assets in the client tenant (directly in DB for speed)
    const [assetA] = await ws.db
      .insert(ws.assetsTable)
      .values({
        tenantId: clientTenantId,
        name: `Granted Asset ${ts}`,
        type: "domain",
        value: `granted-${ts}.invtest.local`,
        verificationStatus: "unverified",
        riskLevel: "info",
        businessImpact: 5,
      })
      .returning();
    grantedAssetId = assetA.id;

    const [assetB] = await ws.db
      .insert(ws.assetsTable)
      .values({
        tenantId: clientTenantId,
        name: `Ungranted Asset ${ts}`,
        type: "domain",
        value: `ungranted-${ts}.invtest.local`,
        verificationStatus: "unverified",
        riskLevel: "info",
        businessImpact: 5,
      })
      .returning();
    ungrantedAssetId = assetB.id;

    // 4. Create a vendor invitation granting only asset A
    const inviteRes = await request(app)
      .post("/api/invitations")
      .set("Authorization", `Bearer ${clientAdminToken}`)
      .send({
        name: `Test Vendor ${ts}`,
        email: `vendor-${ts}@invtest.local`,
        role: "vendor",
        assetIds: [grantedAssetId],
      });
    expect(inviteRes.status, `Create invitation failed: ${JSON.stringify(inviteRes.body)}`).toBe(201);
    validToken = inviteRes.body.token;
    expect(validToken, "invitation token missing").toBeTruthy();
  }, 90_000);

  // ── Cleanup ───────────────────────────────────────────────────────────────

  afterAll(async () => {
    try {
      const { cascadeDeleteTenant } = await import("../tenants");
      const ws = await import("@workspace/db");
      if (clientTenantId) {
        await cascadeDeleteTenant(clientTenantId);
        await ws.db.delete(ws.tenantsTable).where(eq(ws.tenantsTable.id, clientTenantId));
      }
      if (platformTenantId) {
        await cascadeDeleteTenant(platformTenantId);
        await ws.db.delete(ws.tenantsTable).where(eq(ws.tenantsTable.id, platformTenantId));
      }
    } catch {
      // best-effort cleanup
    }
  }, 60_000);

  // ── Error path: invalid token ──────────────────────────────────────────────

  it("GET /auth/invitation-info returns 404 for unknown token", async () => {
    const app = (await import("../../app")).default;
    const res = await request(app).get("/api/auth/invitation-info?token=notarealtoken000");
    expect(res.status).toBe(404);
    expect(res.body.error).toMatch(/not found/i);
  });

  it("POST /auth/accept-invitation returns 404 for unknown token", async () => {
    const app = (await import("../../app")).default;
    const res = await request(app)
      .post("/api/auth/accept-invitation")
      .send({ token: "notarealtoken000", firstName: "A", lastName: "B", password: "Password1!" });
    expect(res.status).toBe(404);
  });

  // ── Error path: missing / short password ──────────────────────────────────

  it("POST /auth/accept-invitation returns 400 when fields are missing", async () => {
    const app = (await import("../../app")).default;
    const res = await request(app)
      .post("/api/auth/accept-invitation")
      .send({ token: validToken }); // missing firstName, lastName, password
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/required/i);
  });

  it("POST /auth/accept-invitation returns 400 for short password", async () => {
    const app = (await import("../../app")).default;
    const res = await request(app)
      .post("/api/auth/accept-invitation")
      .send({ token: validToken, firstName: "Test", lastName: "Vendor", password: "short" });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/8 character/i);
  });

  // ── Error path: expired token ─────────────────────────────────────────────

  it("GET /auth/invitation-info returns 410 for an expired token", async () => {
    const ws = await import("@workspace/db");
    const expiredToken = crypto.randomBytes(32).toString("hex");
    await ws.db.insert(ws.invitationsTable).values({
      tenantId: clientTenantId,
      invitedByUserId: clientAdminUserId,
      name: "Expired Invitee",
      email: `expired-${Date.now()}@invtest.local`,
      role: "vendor",
      assetIds: [grantedAssetId],
      token: expiredToken,
      status: "pending",
      expiresAt: new Date(Date.now() - 1000), // already expired
    });

    const app = (await import("../../app")).default;
    const res = await request(app).get(`/api/auth/invitation-info?token=${expiredToken}`);
    expect(res.status).toBe(410);
    expect(res.body.error).toMatch(/expired/i);
  });

  // ── Happy path: invitation-info pre-fills correctly ───────────────────────

  it("GET /auth/invitation-info returns invitation metadata and asset names", async () => {
    const app = (await import("../../app")).default;
    const res = await request(app).get(`/api/auth/invitation-info?token=${validToken}`);
    expect(res.status, `invitation-info failed: ${JSON.stringify(res.body)}`).toBe(200);
    expect(res.body.email).toMatch(/@invtest\.local$/);
    expect(res.body.role).toBe("vendor");
    expect(Array.isArray(res.body.assetNames)).toBe(true);
    expect(res.body.assetNames.length).toBeGreaterThanOrEqual(1);
    expect(res.body.assetNames.some((n: string) => n.includes("Granted Asset"))).toBe(true);
    expect(res.body.tenantName).toBeTruthy();
  });

  // ── Happy path: accept invitation ─────────────────────────────────────────

  it("POST /auth/accept-invitation creates user, maps assets, returns tokens", async () => {
    const app = (await import("../../app")).default;
    const res = await request(app)
      .post("/api/auth/accept-invitation")
      .send({ token: validToken, firstName: "Test", lastName: "Vendor", password: "Password1!" });

    expect(res.status, `accept-invitation failed: ${JSON.stringify(res.body)}`).toBe(201);
    expect(res.body.accessToken, "accessToken missing from accept-invitation response").toBeTruthy();
    expect(res.body.refreshToken).toBeTruthy();
    expect(res.body.user).toBeDefined();
    expect(res.body.user.role).toBe("vendor");
    expect(res.body.user.firstName).toBe("Test");
    expect(res.body.user.lastName).toBe("Vendor");

    // Capture token and userId for subsequent vendor-access tests
    vendorUserId = res.body.user.id;
    vendorAccessToken = res.body.accessToken;
    expect(vendorUserId, "vendorUserId not set").toBeGreaterThan(0);
    expect(vendorAccessToken, "vendorAccessToken not set").toBeTruthy();
  });

  // ── Error path: already-used token ────────────────────────────────────────

  it("GET /auth/invitation-info returns 410 after token is used", async () => {
    const app = (await import("../../app")).default;
    const res = await request(app).get(`/api/auth/invitation-info?token=${validToken}`);
    expect(res.status).toBe(410);
    expect(res.body.error).toMatch(/already been used/i);
  });

  it("POST /auth/accept-invitation returns 410 when token is already used", async () => {
    const app = (await import("../../app")).default;
    const res = await request(app)
      .post("/api/auth/accept-invitation")
      .send({ token: validToken, firstName: "Test", lastName: "Vendor2", password: "Password1!" });
    expect(res.status).toBe(410);
  });

  // ── Error path: duplicate email ────────────────────────────────────────────

  it("POST /auth/accept-invitation returns 409 when email already exists", async () => {
    const ws = await import("@workspace/db");

    // The vendor user's email is already taken — create a new invitation for the same email
    const [vendorUser] = await ws.db
      .select({ email: ws.usersTable.email })
      .from(ws.usersTable)
      .where(eq(ws.usersTable.id, vendorUserId));

    const dupToken = crypto.randomBytes(32).toString("hex");
    await ws.db.insert(ws.invitationsTable).values({
      tenantId: clientTenantId,
      invitedByUserId: clientAdminUserId,
      name: "Dup Invitee",
      email: vendorUser.email,
      role: "vendor",
      assetIds: [grantedAssetId],
      token: dupToken,
      status: "pending",
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    });

    const app = (await import("../../app")).default;
    const res = await request(app)
      .post("/api/auth/accept-invitation")
      .send({ token: dupToken, firstName: "Dup", lastName: "User", password: "Password1!" });
    expect(res.status).toBe(409);
    expect(res.body.error).toMatch(/already exists/i);
  });

  // ── Asset scoping: vendor sees only granted asset ─────────────────────────

  it("GET /api/assets returns only the granted asset for the vendor", async () => {
    expect(vendorUserId, "vendorUserId not set — accept-invitation test must pass first").toBeGreaterThan(0);
    expect(vendorAccessToken, "vendorAccessToken not set — accept-invitation test must pass first").toBeTruthy();

    const app = (await import("../../app")).default;
    const res = await request(app)
      .get("/api/assets")
      .set("Authorization", `Bearer ${vendorAccessToken}`);
    expect(res.status, `GET /assets failed: ${JSON.stringify(res.body)}`).toBe(200);

    const returnedIds: number[] = res.body.map((a: { id: number }) => a.id);
    expect(returnedIds, "granted asset should be visible").toContain(grantedAssetId);
    expect(returnedIds, "ungranted asset must not be visible").not.toContain(ungrantedAssetId);
    expect(returnedIds.length, "vendor should see exactly 1 asset").toBe(1);
  });

  it("GET /api/assets/:ungrantedId returns 404 for the ungranted asset", async () => {
    expect(vendorAccessToken, "vendorAccessToken not set").toBeTruthy();
    const app = (await import("../../app")).default;
    const res = await request(app)
      .get(`/api/assets/${ungrantedAssetId}`)
      .set("Authorization", `Bearer ${vendorAccessToken}`);
    expect(res.status).toBe(404);
  });

  // ── Findings scoping: only findings for granted assets ────────────────────

  it("GET /api/findings returns only findings for the granted asset", async () => {
    expect(vendorAccessToken, "vendorAccessToken not set").toBeTruthy();
    const ws = await import("@workspace/db");

    // Insert one finding per asset so we can assert scoping
    const ts = Date.now();
    const [grantedFinding] = await ws.db
      .insert(ws.findingsTable)
      .values({
        tenantId: clientTenantId,
        assetId: grantedAssetId,
        title: `Granted Finding ${ts}`,
        severity: "medium",
        status: "open",
        description: "Visible to vendor",
      })
      .returning();

    const [ungrantedFinding] = await ws.db
      .insert(ws.findingsTable)
      .values({
        tenantId: clientTenantId,
        assetId: ungrantedAssetId,
        title: `Ungranted Finding ${ts}`,
        severity: "high",
        status: "open",
        description: "NOT visible to vendor",
      })
      .returning();

    const app = (await import("../../app")).default;
    const res = await request(app)
      .get("/api/findings")
      .set("Authorization", `Bearer ${vendorAccessToken}`);
    expect(res.status, `GET /findings failed: ${JSON.stringify(res.body)}`).toBe(200);

    const returnedIds: number[] = res.body.map((f: { id: number }) => f.id);
    expect(returnedIds, "granted finding should be visible").toContain(grantedFinding.id);
    expect(returnedIds, "ungranted finding must not be visible").not.toContain(ungrantedFinding.id);
  });

  // ── External member cannot POST assets ────────────────────────────────────

  it("POST /api/assets returns 403 for an external member (vendor)", async () => {
    expect(vendorAccessToken, "vendorAccessToken not set").toBeTruthy();
    const app = (await import("../../app")).default;
    const res = await request(app)
      .post("/api/assets")
      .set("Authorization", `Bearer ${vendorAccessToken}`)
      .send({ name: "Rogue Asset", type: "domain", value: "rogue.invtest.local" });
    expect(res.status).toBe(403);
  });

  // ── POST /api/invitations validates external roles require assetIds ────────

  it("POST /api/invitations returns 400 when assetIds omitted for vendor role", async () => {
    const app = (await import("../../app")).default;
    const ts = Date.now();
    const res = await request(app)
      .post("/api/invitations")
      .set("Authorization", `Bearer ${clientAdminToken}`)
      .send({
        name: `No Asset Vendor ${ts}`,
        email: `no-asset-vendor-${ts}@invtest.local`,
        role: "vendor",
        // assetIds intentionally omitted
      });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/asset/i);
  });
});
