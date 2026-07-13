/**
 * Microsoft Graph / Entra ID Integration
 *
 * Uses client credentials (app-only) flow to:
 *  1. List all Enterprise App registrations (service principals)
 *  2. List all consented delegated OAuth2 permission grants per user
 *  3. Enrich with user profile data (email, department, job title)
 *
 * Required platform_settings keys (prefix: shadow_it_azure_):
 *   shadow_it_azure_tenant_id     — Azure tenant ID (GUID)
 *   shadow_it_azure_client_id     — Azure app registration client ID
 *   shadow_it_azure_client_secret — Azure app registration client secret
 *
 * Required Microsoft Entra app permissions (Application, not Delegated):
 *   Application.Read.All
 *   User.Read.All
 *   DelegatedPermissionGrant.ReadWrite.All (or .Read.All)
 */

import { logger } from "../logger";

interface GraphToken {
  access_token: string;
  expires_in: number;
  token_type: string;
}

interface GraphServicePrincipal {
  id: string;
  appId: string;
  displayName: string;
  description?: string;
  homepage?: string;
  publisherName?: string;
  replyUrls?: string[];
  servicePrincipalType?: string;
  tags?: string[];
  appRoles?: Array<{ value: string; displayName: string; description: string }>;
}

interface GraphOAuth2Grant {
  id: string;
  clientId: string;   // service principal ID
  principalId: string; // user object ID (null for admin consent)
  scope: string;       // space-separated list
  consentType: "Principal" | "AllPrincipals";
}

interface GraphUser {
  id: string;
  displayName: string;
  mail?: string;
  userPrincipalName: string;
  department?: string;
  jobTitle?: string;
}

export interface GraphOAuthApp {
  externalId: string;
  servicePrincipalId: string;
  displayName: string;
  appType: "oauth2";
  publisherDomain: string | null;
  homepageUrl: string | null;
  scopes: string[];
  isAdminConsented: boolean;
  users: Array<{
    externalUserId: string;
    userEmail: string;
    userDisplayName: string;
    userDepartment: string | null;
    userJobTitle: string | null;
    scopesGranted: string[];
    isAdminUser: boolean;
  }>;
}

// ── Token fetch ───────────────────────────────────────────────────────────────

async function getAccessToken(tenantId: string, clientId: string, clientSecret: string): Promise<string> {
  const tokenUrl = `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`;
  const res = await fetch(tokenUrl, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "client_credentials",
      client_id: clientId,
      client_secret: clientSecret,
      scope: "https://graph.microsoft.com/.default",
    }),
  });
  if (!res.ok) {
    throw new Error(`Azure token fetch failed: ${res.status} ${await res.text()}`);
  }
  const data = await res.json() as GraphToken;
  return data.access_token;
}

// ── Paginated Graph fetch helper ──────────────────────────────────────────────

async function graphGetAll<T>(accessToken: string, url: string): Promise<T[]> {
  const results: T[] = [];
  let nextUrl: string | null = url;

  while (nextUrl) {
    const res = await fetch(nextUrl, {
      headers: { Authorization: `Bearer ${accessToken}`, ConsistencyLevel: "eventual" },
    });
    if (!res.ok) {
      const body = await res.text();
      throw new Error(`Graph API error ${res.status}: ${body.slice(0, 300)}`);
    }
    const data = await res.json() as { value?: T[]; "@odata.nextLink"?: string };
    results.push(...(data.value ?? []));
    nextUrl = data["@odata.nextLink"] ?? null;
  }

  return results;
}

// ── Main Sync Function ────────────────────────────────────────────────────────

export async function syncMicrosoftGraph(
  tenantId: string,
  clientId: string,
  clientSecret: string,
): Promise<{ apps: GraphOAuthApp[]; usersScanned: number }> {
  logger.info({ tenantId }, "Microsoft Graph: starting sync");

  const token = await getAccessToken(tenantId, clientId, clientSecret);

  // Fetch all in parallel: service principals, oauth grants, users
  const [servicePrincipals, oauthGrants, users] = await Promise.all([
    graphGetAll<GraphServicePrincipal>(
      token,
      "https://graph.microsoft.com/v1.0/servicePrincipals?$select=id,appId,displayName,description,homepage,publisherName,servicePrincipalType,tags&$top=100",
    ),
    graphGetAll<GraphOAuth2Grant>(
      token,
      "https://graph.microsoft.com/v1.0/oauth2PermissionGrants?$top=200",
    ),
    graphGetAll<GraphUser>(
      token,
      "https://graph.microsoft.com/v1.0/users?$select=id,displayName,mail,userPrincipalName,department,jobTitle&$top=200",
    ),
  ]);

  // Build user lookup map
  const userMap = new Map<string, GraphUser>();
  for (const u of users) userMap.set(u.id, u);

  // Filter to only third-party/external enterprise apps (not Microsoft's own)
  const thirdPartyApps = servicePrincipals.filter(sp => {
    // WindowsAzureActiveDirectoryIntegratedApp tag = customer-consented app
    const tags = sp.tags ?? [];
    if (tags.includes("WindowsAzureActiveDirectoryIntegratedApp")) return true;
    // Or: non-Microsoft publisher where there are grants
    if (sp.publisherName && !sp.publisherName.toLowerCase().includes("microsoft")) return true;
    return false;
  });

  logger.info({
    totalSPs: servicePrincipals.length,
    thirdParty: thirdPartyApps.length,
    grants: oauthGrants.length,
  }, "Microsoft Graph: data fetched");

  // Build app map
  const appMap = new Map<string, GraphOAuthApp>();

  for (const sp of thirdPartyApps) {
    appMap.set(sp.id, {
      externalId: sp.appId,
      servicePrincipalId: sp.id,
      displayName: sp.displayName || "Unknown App",
      appType: "oauth2",
      publisherDomain: sp.publisherName ?? null,
      homepageUrl: sp.homepage ?? null,
      scopes: [],
      isAdminConsented: false,
      users: [],
    });
  }

  // Process oauth grants
  for (const grant of oauthGrants) {
    const app = appMap.get(grant.clientId);
    if (!app) continue;

    const scopes = grant.scope.split(" ").filter(Boolean);

    // Admin consent (AllPrincipals) — applies to whole org
    if (grant.consentType === "AllPrincipals") {
      app.isAdminConsented = true;
      for (const s of scopes) {
        if (!app.scopes.includes(s)) app.scopes.push(s);
      }
      continue;
    }

    // Per-user consent
    const user = userMap.get(grant.principalId);
    for (const s of scopes) {
      if (!app.scopes.includes(s)) app.scopes.push(s);
    }
    app.users.push({
      externalUserId: grant.principalId,
      userEmail: user?.mail ?? user?.userPrincipalName ?? grant.principalId,
      userDisplayName: user?.displayName ?? grant.principalId,
      userDepartment: user?.department ?? null,
      userJobTitle: user?.jobTitle ?? null,
      scopesGranted: scopes,
      isAdminUser: false,
    });
  }

  const apps = Array.from(appMap.values()).filter(a => a.scopes.length > 0 || a.isAdminConsented);
  logger.info({ tenantId, apps: apps.length, usersScanned: users.length }, "Microsoft Graph: sync complete");
  return { apps, usersScanned: users.length };
}
