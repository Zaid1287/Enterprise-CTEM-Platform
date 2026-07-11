import { db, alertRulesTable, alertsTable, assetGroupMembersTable } from "@workspace/db";
import { eq, and, inArray } from "drizzle-orm";
import { sendEmail, alertEmailHtml } from "./email";
import { getPlatformSetting } from "../routes/platformSettings";
import { logger } from "./logger";
import { pushSseEvent } from "./sseManager";

export interface NotificationEvent {
  tenantId: number;
  eventType: "scan_complete" | "critical_finding" | "high_finding" | "new_finding" | "brand_threat" | "phishing_detected" | "data_leak_found" | "brand_abuse_found" | "queue_full" | "orchestrator_event" | "tprm_questionnaire_completed" | "tprm_compliance_expiry";
  title: string;
  message: string;
  severity: string;
  scanId?: number;
  findingsCount?: number;
  criticalCount?: number;
  highCount?: number;
  assetName?: string;
  domain?: string;
  sourceFeed?: string;
  relatedAssetId?: number;
  relatedFindingId?: number;
}

const BRAND_THREAT_EVENTS = new Set<NotificationEvent["eventType"]>(["brand_threat", "phishing_detected", "data_leak_found", "brand_abuse_found"]);

function shouldRuleFire(triggerType: string, event: NotificationEvent): boolean {
  switch (triggerType) {
    case "scan_complete":      return event.eventType === "scan_complete";
    case "critical_finding":   return (event.criticalCount ?? 0) > 0;
    case "high_finding":       return (event.highCount ?? 0) > 0 || (event.criticalCount ?? 0) > 0;
    case "new_finding":        return (event.findingsCount ?? 0) > 0;
    case "brand_threat":       return BRAND_THREAT_EVENTS.has(event.eventType);
    case "phishing_detected":  return event.eventType === "phishing_detected";
    case "data_leak_found":    return event.eventType === "data_leak_found";
    case "brand_abuse_found":  return event.eventType === "brand_abuse_found";
    case "queue_full":                    return event.eventType === "queue_full";
    case "orchestrator_event":            return event.eventType === "orchestrator_event";
    case "tprm_questionnaire_completed":  return event.eventType === "tprm_questionnaire_completed";
    case "tprm_compliance_expiry":        return event.eventType === "tprm_compliance_expiry";
    case "any":                           return true;
    default:                              return event.eventType === "scan_complete";
  }
}

function slackPayload(event: NotificationEvent): object {
  const severityEmoji: Record<string, string> = {
    critical: "🔴", high: "🟠", medium: "🟡", low: "🟢", info: "⚪",
  };
  const emoji = severityEmoji[event.severity] ?? "⚪";
  const fields: object[] = [];
  if (event.findingsCount !== undefined)
    fields.push({ type: "mrkdwn", text: `*Total Findings*\n${event.findingsCount}` });
  if (event.criticalCount !== undefined)
    fields.push({ type: "mrkdwn", text: `*Critical*\n${event.criticalCount}` });
  if ((event.highCount ?? 0) > 0)
    fields.push({ type: "mrkdwn", text: `*High*\n${event.highCount}` });
  if (event.assetName)
    fields.push({ type: "mrkdwn", text: `*Asset*\n${event.assetName}` });
  if (event.scanId)
    fields.push({ type: "mrkdwn", text: `*Scan ID*\n#${event.scanId}` });
  return {
    blocks: [
      { type: "header", text: { type: "plain_text", text: `${emoji} Sentinelware CTEM Alert`, emoji: true } },
      { type: "section", text: { type: "mrkdwn", text: `*${event.title}*\n${event.message}` } },
      ...(fields.length > 0 ? [{ type: "section", fields }] : []),
      { type: "divider" },
      { type: "context", elements: [{ type: "mrkdwn", text: `Sentinelware CTEM  •  ${new Date().toUTCString()}` }] },
    ],
  };
}

function discordPayload(event: NotificationEvent): object {
  const severityColor: Record<string, number> = {
    critical: 0xff0000, high: 0xff8800, medium: 0xffcc00, low: 0x00cc44, info: 0x888888,
  };
  const color = severityColor[event.severity] ?? 0x888888;
  const fields: object[] = [];
  if (event.findingsCount !== undefined) fields.push({ name: "Total Findings", value: String(event.findingsCount), inline: true });
  if (event.criticalCount !== undefined) fields.push({ name: "Critical", value: String(event.criticalCount), inline: true });
  if ((event.highCount ?? 0) > 0) fields.push({ name: "High", value: String(event.highCount), inline: true });
  if (event.assetName) fields.push({ name: "Asset", value: event.assetName, inline: true });
  if (event.scanId) fields.push({ name: "Scan ID", value: `#${event.scanId}`, inline: true });
  return {
    embeds: [{
      title: event.title, description: event.message, color, fields,
      footer: { text: "Sentinelware CTEM" },
      timestamp: new Date().toISOString(),
    }],
  };
}

function telegramText(event: NotificationEvent): string {
  const severityEmoji: Record<string, string> = {
    critical: "🔴", high: "🟠", medium: "🟡", low: "🟢", info: "⚪",
  };
  const emoji = severityEmoji[event.severity] ?? "⚪";
  const lines = [
    `${emoji} <b>${escapeHtml(event.title)}</b>`,
    `<i>${escapeHtml(event.message)}</i>`,
    "",
  ];
  if (event.findingsCount !== undefined) lines.push(`📋 Findings: <b>${event.findingsCount}</b>`);
  if (event.criticalCount !== undefined) lines.push(`🔴 Critical: <b>${event.criticalCount}</b>`);
  if ((event.highCount ?? 0) > 0) lines.push(`🟠 High: <b>${event.highCount}</b>`);
  if (event.assetName) lines.push(`🎯 Asset: <b>${escapeHtml(event.assetName)}</b>`);
  if (event.scanId) lines.push(`🔍 Scan: <b>#${event.scanId}</b>`);
  lines.push("", `<i>Sentinelware CTEM • ${new Date().toUTCString()}</i>`);
  return lines.join("\n");
}

function escapeHtml(str: string): string {
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

async function sendTelegram(destination: string, event: NotificationEvent): Promise<void> {
  const parts = destination.split(":");
  if (parts.length < 2) throw new Error("Telegram destination must be botToken:chatId");
  const chatId = parts.pop()!;
  const botToken = parts.join(":");
  const ctrl = new AbortController();
  setTimeout(() => ctrl.abort(), 8000);
  const res = await fetch(`https://api.telegram.org/bot${botToken}/sendMessage`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ chat_id: chatId, text: telegramText(event), parse_mode: "HTML" }),
    signal: ctrl.signal,
  });
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(`Telegram API error ${res.status}: ${body}`);
  }
}

async function postWebhook(url: string, body: object): Promise<void> {
  const ctrl = new AbortController();
  setTimeout(() => ctrl.abort(), 8000);
  const res = await fetch(url, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body), signal: ctrl.signal,
  });
  if (!res.ok) throw new Error(`Webhook POST failed: HTTP ${res.status}`);
}

function genericWebhookPayload(event: NotificationEvent): object {
  return {
    source: "sentinelware", eventType: event.eventType,
    title: event.title, message: event.message, severity: event.severity,
    tenantId: event.tenantId, scanId: event.scanId,
    findingsCount: event.findingsCount, criticalCount: event.criticalCount,
    highCount: event.highCount, assetName: event.assetName,
    domain: event.domain, sourceFeed: event.sourceFeed,
    relatedAssetId: event.relatedAssetId, relatedFindingId: event.relatedFindingId,
    timestamp: new Date().toISOString(),
  };
}

async function insertAlertRecord(event: NotificationEvent): Promise<void> {
  try {
    const [alert] = await db.insert(alertsTable).values({
      tenantId: event.tenantId, title: event.title, message: event.message,
      type: event.eventType, severity: event.severity, isRead: false,
      relatedAssetId: event.relatedAssetId ?? null,
      relatedFindingId: event.relatedFindingId ?? null,
    }).returning();
    pushSseEvent(event.tenantId, "new-alert", {
      id: alert.id, title: alert.title, message: alert.message,
      type: alert.type, severity: alert.severity, isRead: false,
      createdAt: alert.createdAt.toISOString(),
    });
  } catch (err) {
    logger.warn({ err, tenantId: event.tenantId }, "Failed to insert alert record");
  }
}

async function fireTenantRules(event: NotificationEvent): Promise<void> {
  const rules = await db.select().from(alertRulesTable)
    .where(and(eq(alertRulesTable.tenantId, event.tenantId), eq(alertRulesTable.isActive, true)));

  // Pre-load group memberships for any rules that have a groupId filter
  const groupIds = [...new Set(rules.map(r => (r as any).groupId).filter(Boolean) as number[])];
  const groupMemberMap = new Map<number, Set<number>>();
  if (groupIds.length > 0) {
    const memberRows = await db.select({ groupId: assetGroupMembersTable.groupId, assetId: assetGroupMembersTable.assetId })
      .from(assetGroupMembersTable).where(inArray(assetGroupMembersTable.groupId, groupIds));
    for (const row of memberRows) {
      const s = groupMemberMap.get(row.groupId) ?? new Set<number>();
      s.add(row.assetId);
      groupMemberMap.set(row.groupId, s);
    }
  }

  const firedKeys = new Set<string>();
  for (const rule of rules) {
    if (!shouldRuleFire(rule.triggerType, event)) continue;
    // If the rule is scoped to a group, only fire when the event's asset is in that group
    const ruleGroupId = (rule as any).groupId as number | null;
    if (ruleGroupId && event.relatedAssetId) {
      const members = groupMemberMap.get(ruleGroupId);
      if (!members || !members.has(event.relatedAssetId)) continue;
    }

    const dest = rule.destination ||
      await getPlatformSetting(
        rule.channel === "slack"    ? "slack_webhook_url" :
        rule.channel === "discord"  ? "discord_webhook_url" :
        rule.channel === "telegram" ? "telegram_bot_token" : ""
      );
    if (!dest) continue;

    const key = `${rule.channel}:${dest}`;
    if (firedKeys.has(key)) continue;

    try {
      if (rule.channel === "slack") {
        await postWebhook(dest, slackPayload(event));
        firedKeys.add(key);
        logger.info({ tenantId: event.tenantId, ruleId: rule.id }, "Slack notification sent");
      } else if (rule.channel === "discord") {
        await postWebhook(dest, discordPayload(event));
        firedKeys.add(key);
        logger.info({ tenantId: event.tenantId, ruleId: rule.id }, "Discord notification sent");
      } else if (rule.channel === "email") {
        await sendEmail({ to: dest, subject: `[Sentinelware] ${event.title}`, html: alertEmailHtml(event) });
        firedKeys.add(key);
        logger.info({ tenantId: event.tenantId, ruleId: rule.id }, "Alert email sent");
      } else if (rule.channel === "telegram") {
        const telegramDest = rule.destination
          ? dest
          : `${dest}:${await getPlatformSetting("telegram_chat_id") ?? ""}`;
        await sendTelegram(telegramDest, event);
        firedKeys.add(key);
        logger.info({ tenantId: event.tenantId, ruleId: rule.id }, "Telegram notification sent");
      } else if (rule.channel === "webhook") {
        await postWebhook(dest, genericWebhookPayload(event));
        firedKeys.add(key);
        logger.info({ tenantId: event.tenantId, ruleId: rule.id }, "Webhook notification sent");
      }
    } catch (err) {
      logger.warn({ err, channel: rule.channel, ruleId: rule.id }, "Rule notification delivery failed");
    }
  }
}

/**
 * Fire platform-level global fallbacks configured in Platform Settings.
 * These represent the super_admin's global monitoring channels.
 * Should be called ONCE per event, not once per tenant.
 */
async function firePlatformFallbacks(event: NotificationEvent, firedKeys: Set<string>): Promise<void> {
  const [platformSlack, platformDiscord, platformTelegramToken, platformTelegramChat] = await Promise.all([
    getPlatformSetting("slack_webhook_url"),
    getPlatformSetting("discord_webhook_url"),
    getPlatformSetting("telegram_bot_token"),
    getPlatformSetting("telegram_chat_id"),
  ]);

  if (platformSlack && !firedKeys.has(`slack:${platformSlack}`)) {
    try {
      await postWebhook(platformSlack, slackPayload(event));
      firedKeys.add(`slack:${platformSlack}`);
      logger.info({ tenantId: event.tenantId }, "Platform Slack notification sent");
    } catch (err) { logger.warn({ err }, "Platform Slack webhook failed"); }
  }
  if (platformDiscord && !firedKeys.has(`discord:${platformDiscord}`)) {
    try {
      await postWebhook(platformDiscord, discordPayload(event));
      firedKeys.add(`discord:${platformDiscord}`);
      logger.info({ tenantId: event.tenantId }, "Platform Discord notification sent");
    } catch (err) { logger.warn({ err }, "Platform Discord webhook failed"); }
  }
  if (platformTelegramToken && platformTelegramChat) {
    const tKey = `telegram:${platformTelegramToken}:${platformTelegramChat}`;
    if (!firedKeys.has(tKey)) {
      try {
        await sendTelegram(`${platformTelegramToken}:${platformTelegramChat}`, event);
        firedKeys.add(tKey);
        logger.info({ tenantId: event.tenantId }, "Platform Telegram notification sent");
      } catch (err) { logger.warn({ err }, "Platform Telegram notification failed"); }
    }
  }
}

/**
 * Send a notification via a single channel — used by the test endpoint.
 * Does NOT insert a DB alert record or fire platform-level fallbacks.
 */
export async function sendChannelNotification(
  channel: string,
  destination: string,
  event: NotificationEvent,
): Promise<void> {
  if (channel === "email") {
    await sendEmail({ to: destination, subject: `[Sentinelware] ${event.title}`, html: alertEmailHtml(event) });
  } else if (channel === "slack") {
    await postWebhook(destination, slackPayload(event));
  } else if (channel === "discord") {
    await postWebhook(destination, discordPayload(event));
  } else if (channel === "telegram") {
    await sendTelegram(destination, event);
  } else if (channel === "webhook") {
    await postWebhook(destination, genericWebhookPayload(event));
  } else {
    throw new Error(`Unknown channel: ${channel}`);
  }
}

/**
 * Dispatch notifications for a SINGLE tenant only (alert record + tenant rules).
 * Use this when dispatching for multiple tenants from the same scan event
 * to avoid firing platform-level fallbacks multiple times.
 */
export async function dispatchTenantNotifications(event: NotificationEvent): Promise<void> {
  try {
    await insertAlertRecord(event);
    await fireTenantRules(event);
  } catch (err) {
    logger.error({ err, tenantId: event.tenantId }, "dispatchTenantNotifications failed");
  }
}

/**
 * Full dispatch: alert record + tenant rules + platform-level fallbacks.
 * Use this for single-tenant events (brand threats, individual scan completions).
 */
export async function dispatchNotifications(event: NotificationEvent): Promise<void> {
  try {
    await insertAlertRecord(event);
    const firedKeys = new Set<string>();
    await fireTenantRules(event);
    // Platform fallbacks fire once using the triggered tenant's event
    await firePlatformFallbacks(event, firedKeys);
  } catch (err) {
    logger.error({ err, tenantId: event.tenantId }, "dispatchNotifications failed");
  }
}

/**
 * Multi-tenant dispatch: fires tenant rules for EACH tenantId, platform fallbacks ONCE.
 * Use this from pipeline scans where a single scan spans multiple tenant assets.
 */
export async function dispatchMultiTenantNotifications(
  tenantIds: number[],
  event: Omit<NotificationEvent, "tenantId">,
): Promise<void> {
  const unique = [...new Set(tenantIds)];
  // Fire tenant rules for every affected tenant
  for (const tenantId of unique) {
    await dispatchTenantNotifications({ ...event, tenantId });
  }
  // Fire platform fallbacks once (using the first / primary tenant for context)
  const firedKeys = new Set<string>();
  await firePlatformFallbacks({ ...event, tenantId: unique[0] ?? 0 }, firedKeys);
}
