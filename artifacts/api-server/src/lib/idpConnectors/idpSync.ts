/**
 * IdP Sync Orchestrator
 *
 * Routes to the correct IdP connector (Google/Microsoft/Okta), persists
 * results to shadow_it_idp_connections, shadow_it_oauth_apps, and
 * shadow_it_oauth_users, then dispatches alerts for high-risk apps.
 */

import { db, shadowItIdpConnectionsTable, shadowItOauthAppsTable, shadowItOauthUsersTable } from "@workspace/db";
import { eq, and, sql } from "drizzle-orm";
import { logger } from "../logger";
import { syncGoogleWorkspace } from "./googleWorkspace";
import { syncMicrosoftGraph } from "./microsoftGraph";
import { syncOkta } from "./oktaApps";
import { scoreScopes, buildPermissionSummary } from "./scopeRisk";
import { dispatchNotifications } from "../notifier";
import { getPlatformSetting } from "../../routes/platformSettings";

// ── Upsert OAuth app ──────────────────────────────────────────────────────────

async function upsertOauthApp(
  tenantId: number,
  idpConnectionId: number,
  provider: string,
  app: {
    externalId: string;
    displayName: string;
    appType: string;
    publisherDomain: string | null;
    homepageUrl: string | null;
    logoUrl?: string | null;
    scopes: string[];
    isAdminConsented?: boolean;
    isNativeApp?: boolean;
    userCount: number;
  },
): Promise<number> {
  const { level, score, breakdown } = scoreScopes(app.scopes);
  const permSummary = buildPermissionSummary(app.scopes);

  const [row] = await db
    .insert(shadowItOauthAppsTable)
    .values({
      tenantId,
      idpConnectionId,
      provider,
      externalId: app.externalId,
      displayName: app.displayName,
      appType: app.appType,
      publisherDomain: app.publisherDomain,
      homepageUrl: app.homepageUrl,
      logoUrl: app.logoUrl ?? null,
      scopes: app.scopes,
      permissionSummary: permSummary,
      riskScore: score,
      riskLevel: level,
      riskFactors: breakdown,
      userCount: app.userCount,
      isAdminConsented: app.isAdminConsented ?? false,
      isSanctioned: false,
      status: "active",
      lastSeenAt: new Date(),
    })
    .onConflictDoUpdate({
      target: [shadowItOauthAppsTable.tenantId, shadowItOauthAppsTable.provider, shadowItOauthAppsTable.externalId],
      set: {
        displayName: app.displayName,
        scopes: app.scopes,
        permissionSummary: permSummary,
        riskScore: score,
        riskLevel: level,
        riskFactors: breakdown,
        userCount: app.userCount,
        lastSeenAt: new Date(),
        updatedAt: new Date(),
      },
    })
    .returning({ id: shadowItOauthAppsTable.id });

  return row.id;
}

// ── Upsert OAuth user attribution ─────────────────────────────────────────────

async function upsertOauthUser(
  tenantId: number,
  idpConnectionId: number,
  oauthAppId: number,
  user: {
    externalUserId: string;
    userEmail: string;
    userDisplayName: string;
    userDepartment?: string | null;
    userJobTitle?: string | null;
    scopesGranted: string[];
    isAdminUser: boolean;
  },
): Promise<void> {
  const { level } = scoreScopes(user.scopesGranted);
  await db
    .insert(shadowItOauthUsersTable)
    .values({
      tenantId,
      idpConnectionId,
      oauthAppId,
      externalUserId: user.externalUserId,
      userEmail: user.userEmail,
      userDisplayName: user.userDisplayName,
      userDepartment: user.userDepartment ?? null,
      userJobTitle: user.userJobTitle ?? null,
      scopesGranted: user.scopesGranted,
      riskLevel: level,
      isAdminUser: user.isAdminUser,
    })
    .onConflictDoUpdate({
      target: [shadowItOauthUsersTable.tenantId, shadowItOauthUsersTable.oauthAppId, shadowItOauthUsersTable.externalUserId],
      set: {
        scopesGranted: user.scopesGranted,
        riskLevel: level,
        isAdminUser: user.isAdminUser,
        updatedAt: new Date(),
      },
    });
}

// ── Update connection status ──────────────────────────────────────────────────

async function updateConnectionStatus(
  connectionId: number,
  status: "success" | "failed",
  opts: { syncedApps?: number; syncedUsers?: number; error?: string } = {},
): Promise<void> {
  await db
    .update(shadowItIdpConnectionsTable)
    .set({
      lastSyncAt: new Date(),
      lastSyncStatus: status,
      lastSyncError: opts.error ?? null,
      syncedApps: opts.syncedApps ?? 0,
      syncedUsers: opts.syncedUsers ?? 0,
      updatedAt: new Date(),
    })
    .where(eq(shadowItIdpConnectionsTable.id, connectionId));
}

// ── Per-provider sync ─────────────────────────────────────────────────────────

export async function syncIdpConnection(connectionId: number, tenantId: number): Promise<{
  syncedApps: number;
  syncedUsers: number;
}> {
  const [conn] = await db
    .select()
    .from(shadowItIdpConnectionsTable)
    .where(and(eq(shadowItIdpConnectionsTable.id, connectionId), eq(shadowItIdpConnectionsTable.tenantId, tenantId)));

  if (!conn) throw new Error(`IdP connection ${connectionId} not found`);
  if (!conn.isActive) throw new Error(`IdP connection ${connectionId} is inactive`);

  logger.info({ provider: conn.provider, connectionId }, "IdP sync started");

  try {
    let allApps: Array<{
      externalId: string;
      displayName: string;
      appType: string;
      publisherDomain: string | null;
      homepageUrl: string | null;
      logoUrl?: string | null;
      scopes: string[];
      isAdminConsented?: boolean;
      users: Array<{
        externalUserId: string;
        userEmail: string;
        userDisplayName: string;
        userDepartment?: string | null;
        userJobTitle?: string | null;
        scopesGranted: string[];
        isAdminUser: boolean;
      }>;
    }> = [];
    let usersScanned = 0;

    if (conn.provider === "google_workspace") {
      const saJson = await getPlatformSetting(`shadow_it_google_sa_json`);
      if (!saJson) throw new Error("Google Workspace: shadow_it_google_sa_json not configured in platform settings");
      const adminEmail = conn.configEmail;
      if (!adminEmail) throw new Error("Google Workspace: admin email not configured");
      const result = await syncGoogleWorkspace(saJson, adminEmail);
      allApps = result.apps;
      usersScanned = result.usersScanned;

    } else if (conn.provider === "microsoft_graph") {
      const clientSecret = await getPlatformSetting(`shadow_it_azure_client_secret`);
      if (!conn.configTenantId) throw new Error("Azure: tenant ID not configured");
      if (!conn.configClientId) throw new Error("Azure: client ID not configured");
      if (!clientSecret) throw new Error("Azure: shadow_it_azure_client_secret not configured in platform settings");
      const result = await syncMicrosoftGraph(conn.configTenantId, conn.configClientId, clientSecret);
      allApps = result.apps;
      usersScanned = result.usersScanned;

    } else if (conn.provider === "okta") {
      const apiToken = await getPlatformSetting(`shadow_it_okta_api_token`);
      if (!conn.configDomain) throw new Error("Okta: domain not configured");
      if (!apiToken) throw new Error("Okta: shadow_it_okta_api_token not configured in platform settings");
      const result = await syncOkta(conn.configDomain, apiToken);
      allApps = result.apps.map(a => ({ ...a, publisherDomain: null as string | null }));
      usersScanned = result.usersScanned;

    } else {
      throw new Error(`Unknown IdP provider: ${conn.provider}`);
    }

    // Persist all apps and user attributions
    let appCount = 0;
    let userCount = 0;
    const criticalApps: string[] = [];

    for (const app of allApps) {
      const appId = await upsertOauthApp(tenantId, connectionId, conn.provider, {
        ...app,
        userCount: app.users.length,
      });
      appCount++;

      const { level } = scoreScopes(app.scopes);
      if (level === "critical") criticalApps.push(app.displayName);

      for (const user of app.users) {
        await upsertOauthUser(tenantId, connectionId, appId, user);
        userCount++;
      }
    }

    await updateConnectionStatus(connectionId, "success", { syncedApps: appCount, syncedUsers: usersScanned });

    // Alert on new critical-risk apps
    if (criticalApps.length > 0) {
      setImmediate(() => {
        dispatchNotifications({
          tenantId,
          eventType: "shadow_it_discovered",
          title: `Shadow IT: ${criticalApps.length} Critical-Risk SaaS App${criticalApps.length > 1 ? "s" : ""} Found`,
          message: `${criticalApps.length} app${criticalApps.length > 1 ? "s" : ""} with admin/critical-level OAuth scopes discovered via ${conn.displayName}.\n\nApps: ${criticalApps.slice(0, 5).join(", ")}${criticalApps.length > 5 ? ` +${criticalApps.length - 5} more` : ""}`,
          severity: "critical",
          findingsCount: criticalApps.length,
          criticalCount: criticalApps.length,
          highCount: 0,
        }).catch(err => logger.warn({ err }, "Shadow IT IdP alert dispatch failed"));
      });
    }

    logger.info({ provider: conn.provider, appCount, userCount }, "IdP sync complete");
    return { syncedApps: appCount, syncedUsers: usersScanned };

  } catch (err: any) {
    const errMsg = err?.message ?? String(err);
    await updateConnectionStatus(connectionId, "failed", { error: errMsg.slice(0, 500) });
    throw err;
  }
}

// ── Sync all active connections for a tenant ──────────────────────────────────

export async function syncAllIdpConnections(tenantId: number): Promise<void> {
  const connections = await db
    .select()
    .from(shadowItIdpConnectionsTable)
    .where(and(eq(shadowItIdpConnectionsTable.tenantId, tenantId), eq(shadowItIdpConnectionsTable.isActive, true)));

  for (const conn of connections) {
    await syncIdpConnection(conn.id, tenantId).catch(err =>
      logger.warn({ err, connectionId: conn.id }, "IdP sync failed for connection (non-fatal)")
    );
  }
}
