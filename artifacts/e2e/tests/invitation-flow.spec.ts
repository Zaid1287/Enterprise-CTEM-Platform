/**
 * E2E: Invite → Accept → Login flow
 *
 * Covers the full browser journey a vendor takes when they receive an invitation:
 *   1. Admin creates an invitation via POST /api/invitations
 *   2. Vendor visits /accept-invitation?token=... in a real browser
 *   3. Vendor fills the account-creation form and submits
 *   4. Page shows "Account Created!" then auto-navigates to /assets
 *   5. Vendor's /assets view only shows the asset they were granted
 *   6. Error states: invalid token and missing token show "Invitation Error"
 *
 * Prerequisites: both the API server (port 8080) and the frontend (port 23203)
 * must be running and proxied behind localhost:80.
 *
 * Each test that calls accept-invitation creates its own unique invitation so
 * that single-use token consumption across tests does not cause false failures.
 */

import { test, expect } from "@playwright/test";

const API = "http://localhost:80/api";

/** POST helper — throws on non-2xx */
async function apiPost(path: string, body: unknown, token?: string) {
  const res = await fetch(`${API}${path}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`POST ${path} → ${res.status}: ${text}`);
  }
  return res.json() as Promise<Record<string, unknown>>;
}

/** GET helper — throws on non-2xx */
async function apiGet(path: string, token: string) {
  const res = await fetch(`${API}${path}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`GET ${path} → ${res.status}: ${text}`);
  }
  return res.json() as Promise<unknown>;
}

/** Creates a fresh platform tenant + SA token + granted asset, returns shared context. */
async function setupPlatformContext(uniqueTs: number) {
  const reg = await apiPost("/auth/register", {
    tenantName: `E2EPlatform${uniqueTs}`,
    email: `sa-${uniqueTs}@e2etest.local`,
    password: "Sup3rAdm1n!",
    firstName: "SA",
    lastName: "Test",
  });
  const saToken = reg.accessToken as string;

  const assetName = `GrantedAsset${uniqueTs}`;
  const asset = await apiPost(
    "/assets",
    { name: assetName, type: "domain", value: `granted-${uniqueTs}.e2etest.local` },
    saToken
  );
  const assetId = asset.id as number;

  return { saToken, assetId, assetName };
}

/** Creates a fresh invitation for a vendor. Returns the token + email. */
async function createInvitation(saToken: string, assetId: number, uniqueTs: number) {
  const email = `vendor-${uniqueTs}@e2etest.local`;
  const inv = await apiPost(
    "/invitations",
    { name: "E2E Vendor", email, role: "vendor", assetIds: [assetId] },
    saToken
  );
  return { token: inv.token as string, email };
}

// ─────────────────────────────────────────────────────────────
// Main happy-path test
// ─────────────────────────────────────────────────────────────

test("vendor accepts invitation and is redirected to /assets", async ({ page }) => {
  const ts = Date.now();
  const { saToken, assetId, assetName } = await setupPlatformContext(ts);
  const { token: inviteToken, email: vendorEmail } = await createInvitation(saToken, assetId, ts);

  // ── Navigate to the accept-invitation page ──
  await page.goto(`/accept-invitation?token=${encodeURIComponent(inviteToken)}`);

  // ── Verify the form loaded with correct invitation data ──
  await expect(
    page.getByRole("heading", { name: "Accept Your Invitation" })
  ).toBeVisible();

  // Email is pre-filled as a read-only input — verify it is visible on the page
  await expect(page.locator(`input[readonly][value="${vendorEmail}"]`)).toBeVisible();

  // Granted asset name appears in the "You will have access to:" panel
  await expect(page.getByText(assetName)).toBeVisible();

  // ── Fill the account-creation form (use placeholders — ShadCN Label has no htmlFor) ──
  await page.getByPlaceholder("Jane").clear();
  await page.getByPlaceholder("Jane").fill("Tester");

  await page.getByPlaceholder("Smith").clear();
  await page.getByPlaceholder("Smith").fill("Vendor");

  await page.getByPlaceholder("At least 8 characters").fill("V3ndorPass!");
  await page.getByPlaceholder("Re-enter your password").fill("V3ndorPass!");

  // ── Submit ──
  await page.getByRole("button", { name: /create account/i }).click();

  // ── After submit the page briefly shows "Account Created!" then auto-redirects. ──
  // We wait for the redirect rather than the ephemeral 1200 ms success screen.
  await page.waitForURL("**/assets**", { timeout: 15_000 });

  // ── Verify landing on /assets ──
  expect(page.url()).toMatch(/\/assets/);
  await expect(page.getByText(/forbidden|403/i)).not.toBeVisible();

  // ── Granted asset must appear in the vendor's asset list ──
  await expect(page.getByText(assetName)).toBeVisible({ timeout: 10_000 });
});

// ─────────────────────────────────────────────────────────────
// Scoping test — vendor sees only granted assets + findings
// ─────────────────────────────────────────────────────────────

test("vendor /api/assets and /api/findings are scoped to granted asset only", async ({ page }) => {
  const ts = Date.now() + 1; // offset to avoid potential ms collision with test above
  const SKIP = !process.env.DATABASE_URL;

  // ── Setup: one tenant, two assets, only one granted to the vendor ──
  const reg = await apiPost("/auth/register", {
    tenantName: `E2EScope${ts}`,
    email: `scope-sa-${ts}@e2etest.local`,
    password: "Sup3rAdm1n!",
    firstName: "Scope",
    lastName: "SA",
  });
  const saToken = reg.accessToken as string;
  const tenantId = (reg.user as Record<string, unknown>).tenantId as number;

  // Create the asset that WILL be granted
  const grantedAssetName = `ScopeGranted${ts}`;
  const grantedAsset = await apiPost(
    "/assets",
    { name: grantedAssetName, type: "domain", value: `sg-${ts}.e2etest.local` },
    saToken
  );
  const grantedAssetId = grantedAsset.id as number;

  // Create the asset that will NOT be granted
  const ungrantedAssetName = `ScopeUngranted${ts}`;
  const ungrantedAsset = await apiPost(
    "/assets",
    { name: ungrantedAssetName, type: "domain", value: `su-${ts}.e2etest.local` },
    saToken
  );
  const ungrantedAssetId = ungrantedAsset.id as number;

  // Seed one finding per asset via DB so we can test /api/findings scoping.
  // Skipped when DATABASE_URL is not available (non-DB environment).
  let grantedFindingId = -1;
  let ungrantedFindingId = -1;
  if (!SKIP) {
    const ws = await import("@workspace/db");
    const [gf] = await ws.db
      .insert(ws.findingsTable)
      .values({
        tenantId,
        assetId: grantedAssetId,
        title: `ScopeFinding-Granted-${ts}`,
        severity: "high",
        status: "open",
      })
      .returning({ id: ws.findingsTable.id });
    grantedFindingId = gf.id;

    const [uf] = await ws.db
      .insert(ws.findingsTable)
      .values({
        tenantId,
        assetId: ungrantedAssetId,
        title: `ScopeFinding-Ungranted-${ts}`,
        severity: "critical",
        status: "open",
      })
      .returning({ id: ws.findingsTable.id });
    ungrantedFindingId = uf.id;
  }

  // Create invitation with ONLY the granted asset
  const vendorEmail = `scope-vendor-${ts}@e2etest.local`;
  const inv = await apiPost(
    "/invitations",
    { name: "Scope Vendor", email: vendorEmail, role: "vendor", assetIds: [grantedAssetId] },
    saToken
  );
  const inviteToken = inv.token as string;

  // ── Browser: accept invitation ──
  await page.goto(`/accept-invitation?token=${encodeURIComponent(inviteToken)}`);
  await expect(page.getByRole("heading", { name: "Accept Your Invitation" })).toBeVisible();

  // Access panel shows only the granted asset
  await expect(page.getByText(grantedAssetName)).toBeVisible();
  await expect(page.getByText(ungrantedAssetName)).not.toBeVisible();

  await page.getByPlaceholder("Jane").clear();
  await page.getByPlaceholder("Jane").fill("Scope");
  await page.getByPlaceholder("Smith").clear();
  await page.getByPlaceholder("Smith").fill("Vendor");
  await page.getByPlaceholder("At least 8 characters").fill("V3ndorPass!");
  await page.getByPlaceholder("Re-enter your password").fill("V3ndorPass!");
  await page.getByRole("button", { name: /create account/i }).click();
  await page.waitForURL("**/assets**", { timeout: 15_000 });

  // ── Extract vendor token from sessionStorage ──
  const vendorToken = await page.evaluate(
    () => sessionStorage.getItem("ctem_token") ?? ""
  );
  expect(vendorToken).toBeTruthy();

  // ── Assert /api/assets scoping ──
  const rawAssets = await apiGet("/assets", vendorToken);
  const assets = (
    Array.isArray(rawAssets)
      ? rawAssets
      : ((rawAssets as Record<string, unknown>).assets ??
         (rawAssets as Record<string, unknown>).data ??
         [])
  ) as Array<{ id: number; name: string }>;

  expect(assets.some((a) => a.id === grantedAssetId), "granted asset must be visible").toBe(true);
  expect(assets.some((a) => a.id === ungrantedAssetId), "ungranted same-tenant asset must be hidden").toBe(false);

  // ── Assert /api/findings scoping (only when findings were seeded) ──
  if (!SKIP && grantedFindingId !== -1) {
    const rawFindings = await apiGet("/findings", vendorToken);
    const findings = (
      Array.isArray(rawFindings)
        ? rawFindings
        : ((rawFindings as Record<string, unknown>).findings ??
           (rawFindings as Record<string, unknown>).data ??
           [])
    ) as Array<{ id: number }>;

    expect(findings.some((f) => f.id === grantedFindingId), "granted-asset finding must be visible").toBe(true);
    expect(findings.some((f) => f.id === ungrantedFindingId), "ungranted-asset finding must be hidden").toBe(false);
  }
});

// ─────────────────────────────────────────────────────────────
// Error-state tests — no setup needed
// ─────────────────────────────────────────────────────────────

test("shows Invitation Error for an invalid token", async ({ page }) => {
  await page.goto("/accept-invitation?token=totally-invalid-token-xyz");
  await expect(
    page.getByRole("heading", { name: "Invitation Error" })
  ).toBeVisible({ timeout: 10_000 });
  // API returns "Invitation not found" for unknown tokens
  await expect(page.getByText(/invitation not found/i)).toBeVisible();
});

test("shows Invitation Error when no token is in the URL", async ({ page }) => {
  await page.goto("/accept-invitation");
  await expect(
    page.getByRole("heading", { name: "Invitation Error" })
  ).toBeVisible({ timeout: 10_000 });
  await expect(page.getByText(/no invitation token/i)).toBeVisible();
});
