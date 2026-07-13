/**
 * Okta Apps API Integration
 *
 * Uses an Okta API token to:
 *  1. List all SAML, OIDC, and OAuth applications in the Okta tenant
 *  2. For each app, list assigned users with their profile data
 *
 * Required platform_settings keys:
 *   shadow_it_okta_domain     — Okta domain (e.g., mycompany.okta.com)
 *   shadow_it_okta_api_token  — Okta API token (starts with SSWS)
 *
 * Required API token scopes:
 *   okta.apps.read
 *   okta.users.read
 */

import { logger } from "../logger";

interface OktaApp {
  id: string;
  name: string;
  label: string;
  status: string;
  signOnMode: string;
  created: string;
  lastUpdated: string;
  accessibility?: { selfService?: boolean };
  visibility?: { autoSubmitToolbar?: boolean };
  settings?: {
    oauthClient?: {
      client_uri?: string;
      logo_uri?: string;
      grant_types?: string[];
      response_types?: string[];
      redirect_uris?: string[];
      token_endpoint_auth_method?: string;
    };
    saml?: {
      spIssuer?: string;
      idpIssuer?: string;
    };
  };
  _links?: { appLinks?: Array<{ href: string; name: string }> };
}

interface OktaAppUser {
  id: string;
  status: string;
  created: string;
  profile: {
    login?: string;
    email?: string;
    firstName?: string;
    lastName?: string;
    department?: string;
    title?: string;
  };
  credentials?: {
    userName?: string;
  };
  scope?: string;
}

export interface OktaOAuthApp {
  externalId: string;
  displayName: string;
  appType: "saml" | "oidc" | "oauth2" | "bookmark" | "other";
  signOnMode: string;
  homepageUrl: string | null;
  logoUrl: string | null;
  scopes: string[];
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

// ── Paginated Okta fetch helper ───────────────────────────────────────────────

async function oktaGetAll<T>(domain: string, apiToken: string, path: string): Promise<T[]> {
  const results: T[] = [];
  let url: string | null = `https://${domain}${path}`;

  while (url) {
    const res = await fetch(url, {
      headers: { Authorization: `SSWS ${apiToken}`, Accept: "application/json" },
    });
    if (!res.ok) {
      const body = await res.text();
      throw new Error(`Okta API error ${res.status}: ${body.slice(0, 300)}`);
    }
    const items = await res.json() as T[];
    results.push(...items);

    // Okta uses Link header for pagination
    const linkHeader = res.headers.get("Link") ?? "";
    const nextMatch = linkHeader.match(/<([^>]+)>;\s*rel="next"/);
    url = nextMatch ? nextMatch[1] : null;
  }

  return results;
}

function mapSignOnMode(mode: string): OktaOAuthApp["appType"] {
  if (mode.startsWith("SAML")) return "saml";
  if (mode === "OPENID_CONNECT") return "oidc";
  if (mode === "BROWSER_PLUGIN" || mode === "AUTO_LOGIN") return "oauth2";
  if (mode === "BOOKMARK") return "bookmark";
  return "other";
}

// ── Main Sync Function ────────────────────────────────────────────────────────

export async function syncOkta(
  domain: string,
  apiToken: string,
): Promise<{ apps: OktaOAuthApp[]; usersScanned: number }> {
  logger.info({ domain }, "Okta: starting sync");

  // List all active apps
  const oktaApps = await oktaGetAll<OktaApp>(
    domain, apiToken,
    "/api/v1/apps?limit=200&filter=status+eq+%22ACTIVE%22",
  );

  logger.info({ domain, count: oktaApps.length }, "Okta: apps listed");

  // Get all users for counting unique users
  const allUsers = await oktaGetAll<{ id: string; profile: { login: string; email?: string; firstName?: string; lastName?: string; department?: string; title?: string } }>(
    domain, apiToken,
    "/api/v1/users?limit=200&filter=status+eq+%22ACTIVE%22",
  ).catch(() => []);

  const userSet = new Set(allUsers.map(u => u.id));

  // For each app, get assigned users
  const apps: OktaOAuthApp[] = [];

  for (const app of oktaApps) {
    // Skip internal Okta apps
    if (app.name.startsWith("okta_") || app.name === "okta") continue;

    let appUsers: OktaAppUser[] = [];
    try {
      appUsers = await oktaGetAll<OktaAppUser>(
        domain, apiToken,
        `/api/v1/apps/${app.id}/users?limit=100`,
      );
    } catch {
      // Non-fatal: just record without users
    }

    const grantTypes = app.settings?.oauthClient?.grant_types ?? [];
    const scopes = grantTypes.length > 0 ? grantTypes : [];

    apps.push({
      externalId: app.id,
      displayName: app.label || app.name,
      appType: mapSignOnMode(app.signOnMode),
      signOnMode: app.signOnMode,
      homepageUrl: app.settings?.oauthClient?.client_uri ?? null,
      logoUrl: app.settings?.oauthClient?.logo_uri ?? null,
      scopes,
      users: appUsers.map(u => ({
        externalUserId: u.id,
        userEmail: u.profile?.email ?? u.profile?.login ?? u.credentials?.userName ?? u.id,
        userDisplayName: `${u.profile?.firstName ?? ""} ${u.profile?.lastName ?? ""}`.trim() || u.id,
        userDepartment: u.profile?.department ?? null,
        userJobTitle: u.profile?.title ?? null,
        scopesGranted: scopes,
        isAdminUser: false,
      })),
    });

    // Throttle
    await new Promise(r => setTimeout(r, 50));
  }

  logger.info({ domain, apps: apps.length, usersScanned: userSet.size }, "Okta: sync complete");
  return { apps, usersScanned: userSet.size };
}
