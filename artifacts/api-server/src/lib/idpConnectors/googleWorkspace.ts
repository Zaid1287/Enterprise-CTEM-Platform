/**
 * Google Workspace Admin SDK Integration
 *
 * Uses a service account with domain-wide delegation to:
 *  1. List all users in the Google Workspace domain
 *  2. For each user, enumerate their authorized OAuth tokens (third-party apps)
 *
 * Required platform_settings keys (prefix: shadow_it_google_):
 *   shadow_it_google_sa_json     — full service account JSON key (as string)
 *   shadow_it_google_admin_email — the super admin email to impersonate
 *
 * Required service account:
 *   - Domain-Wide Delegation enabled
 *   - Delegated scopes in Google Admin Console:
 *     https://www.googleapis.com/auth/admin.directory.user.readonly
 *     https://www.googleapis.com/auth/admin.directory.user.security
 */

import { createSign } from "crypto";
import { logger } from "../logger";
import { scoreScopes, buildPermissionSummary } from "./scopeRisk";

interface ServiceAccountKey {
  type: string;
  project_id: string;
  private_key_id: string;
  private_key: string;
  client_email: string;
  token_uri: string;
}

interface GWorkspaceUser {
  id: string;
  primaryEmail: string;
  name: { fullName: string };
  orgUnitPath?: string;
  isAdmin?: boolean;
  suspended?: boolean;
}

interface GWorkspaceToken {
  clientId: string;
  displayText: string;
  etag: string;
  kind: string;
  nativeApp: boolean;
  anonymous?: boolean;
  scopes?: string[];
  userKey: string;
}

export interface WorkspaceOAuthApp {
  externalId: string;
  displayName: string;
  appType: "oauth2";
  publisherDomain: string | null;
  homepageUrl: string | null;
  scopes: string[];
  isNativeApp: boolean;
  users: Array<{
    externalUserId: string;
    userEmail: string;
    userDisplayName: string;
    scopesGranted: string[];
    isAdminUser: boolean;
  }>;
}

// ── JWT Service Account Auth ──────────────────────────────────────────────────

function makeJwt(
  serviceAccount: ServiceAccountKey,
  impersonateEmail: string,
  scopes: string[],
): string {
  const now = Math.floor(Date.now() / 1000);
  const header = Buffer.from(JSON.stringify({ alg: "RS256", typ: "JWT" })).toString("base64url");
  const payload = Buffer.from(JSON.stringify({
    iss: serviceAccount.client_email,
    sub: impersonateEmail,
    scope: scopes.join(" "),
    aud: serviceAccount.token_uri || "https://oauth2.googleapis.com/token",
    iat: now,
    exp: now + 3600,
  })).toString("base64url");

  const signingInput = `${header}.${payload}`;
  const signer = createSign("RSA-SHA256");
  signer.update(signingInput);
  const signature = signer.sign(serviceAccount.private_key, "base64url");
  return `${signingInput}.${signature}`;
}

async function getAccessToken(
  serviceAccount: ServiceAccountKey,
  impersonateEmail: string,
  scopes: string[],
): Promise<string> {
  const jwt = makeJwt(serviceAccount, impersonateEmail, scopes);
  const res = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
      assertion: jwt,
    }),
  });
  if (!res.ok) {
    const err = await res.text();
    throw new Error(`Google token exchange failed: ${res.status} ${err}`);
  }
  const data = await res.json() as { access_token: string };
  return data.access_token;
}

async function listAllUsers(accessToken: string, domain: string): Promise<GWorkspaceUser[]> {
  const users: GWorkspaceUser[] = [];
  let pageToken: string | undefined;

  do {
    const url = new URL("https://admin.googleapis.com/admin/directory/v1/users");
    url.searchParams.set("customer", "my_customer");
    url.searchParams.set("domain", domain);
    url.searchParams.set("maxResults", "200");
    url.searchParams.set("projection", "basic");
    if (pageToken) url.searchParams.set("pageToken", pageToken);

    const res = await fetch(url.toString(), {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    if (!res.ok) throw new Error(`List users failed: ${res.status} ${await res.text()}`);

    const data = await res.json() as { users?: GWorkspaceUser[]; nextPageToken?: string };
    users.push(...(data.users ?? []));
    pageToken = data.nextPageToken;
  } while (pageToken);

  return users;
}

async function listUserTokens(accessToken: string, userEmail: string): Promise<GWorkspaceToken[]> {
  const url = `https://admin.googleapis.com/admin/directory/v1/users/${encodeURIComponent(userEmail)}/tokens`;
  const res = await fetch(url, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  if (res.status === 404 || res.status === 403) return [];
  if (!res.ok) {
    logger.debug({ status: res.status, userEmail }, "Google: listUserTokens non-fatal error");
    return [];
  }
  const data = await res.json() as { items?: GWorkspaceToken[] };
  return data.items ?? [];
}

// ── Main Sync Function ────────────────────────────────────────────────────────

export async function syncGoogleWorkspace(
  saJson: string,
  adminEmail: string,
): Promise<{ apps: WorkspaceOAuthApp[]; usersScanned: number }> {
  const serviceAccount = JSON.parse(saJson) as ServiceAccountKey;
  const domain = adminEmail.split("@")[1];
  if (!domain) throw new Error("Invalid admin email — cannot extract domain");

  logger.info({ domain }, "Google Workspace: starting sync");

  // Get admin access token
  const adminToken = await getAccessToken(serviceAccount, adminEmail, [
    "https://www.googleapis.com/auth/admin.directory.user.readonly",
    "https://www.googleapis.com/auth/admin.directory.user.security",
  ]);

  // List all users
  const users = await listAllUsers(adminToken, domain);
  logger.info({ count: users.length, domain }, "Google Workspace: users listed");

  // For each user, get their tokens — rate-limited to avoid 429
  const appMap = new Map<string, WorkspaceOAuthApp>();

  for (let i = 0; i < users.length; i++) {
    const user = users[i];
    if (user.suspended) continue;

    const tokens = await listUserTokens(adminToken, user.primaryEmail);
    for (const token of tokens) {
      if (!token.clientId) continue;

      const existing = appMap.get(token.clientId);
      const scopesGranted = token.scopes ?? [];
      const userEntry = {
        externalUserId: user.id,
        userEmail: user.primaryEmail,
        userDisplayName: user.name?.fullName ?? user.primaryEmail,
        scopesGranted,
        isAdminUser: user.isAdmin ?? false,
      };

      if (existing) {
        existing.users.push(userEntry);
        // Merge scopes
        for (const s of scopesGranted) {
          if (!existing.scopes.includes(s)) existing.scopes.push(s);
        }
        existing.users.length && (existing.users[existing.users.length - 1]);
      } else {
        appMap.set(token.clientId, {
          externalId: token.clientId,
          displayName: token.displayText || `App (${token.clientId})`,
          appType: "oauth2",
          publisherDomain: null,
          homepageUrl: null,
          scopes: scopesGranted,
          isNativeApp: token.nativeApp,
          users: [userEntry],
        });
      }
    }

    // Throttle: 1 req per 100ms to stay within Google's quota
    if (i % 10 === 0) await new Promise(r => setTimeout(r, 100));
  }

  const apps = Array.from(appMap.values());
  logger.info({ domain, apps: apps.length, usersScanned: users.length }, "Google Workspace: sync complete");
  return { apps, usersScanned: users.length };
}
