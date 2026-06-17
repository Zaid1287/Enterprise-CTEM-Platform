import { db, alertRulesTable } from "@workspace/db";
import { eq, and } from "drizzle-orm";
import { sendEmail, alertEmailHtml } from "./email";
import { getPlatformSetting } from "../routes/platformSettings";
import { logger } from "./logger";

export interface NotificationEvent {
  tenantId: number;
  eventType: "scan_complete" | "critical_finding" | "high_finding" | "new_finding" | "brand_threat";
  title: string;
  message: string;
  severity: string;
  scanId?: number;
  findingsCount?: number;
  criticalCount?: number;
  highCount?: number;
  assetName?: string;
  domain?: string;
}

function shouldRuleFire(triggerType: string, event: NotificationEvent): boolean {
  switch (triggerType) {
    case "scan_complete":    return event.eventType === "scan_complete";
    case "critical_finding": return (event.criticalCount ?? 0) > 0;
    case "high_finding":     return (event.highCount ?? 0) > 0 || (event.criticalCount ?? 0) > 0;
    case "new_finding":      return (event.findingsCount ?? 0) > 0;
    case "brand_threat":     return event.eventType === "brand_threat";
    case "any":              return true;
    default:                 return event.eventType === "scan_complete";
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
      title: event.title,
      description: event.message,
      color,
      fields,
      footer: { text: "Sentinelware CTEM" },
      timestamp: new Date().toISOString(),
    }],
  };
}

async function postWebhook(url: string, body: object): Promise<void> {
  const ctrl = new AbortController();
  setTimeout(() => ctrl.abort(), 8000);
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
    signal: ctrl.signal,
  });
  if (!res.ok) throw new Error(`Webhook POST failed: HTTP ${res.status}`);
}

export async function dispatchNotifications(event: NotificationEvent): Promise<void> {
  try {
    const rules = await db.select().from(alertRulesTable)
      .where(and(eq(alertRulesTable.tenantId, event.tenantId), eq(alertRulesTable.isActive, true)));

    const firedKeys = new Set<string>();

    for (const rule of rules) {
      if (!shouldRuleFire(rule.triggerType, event)) continue;

      const dest = rule.destination ||
        await getPlatformSetting(
          rule.channel === "slack"   ? "slack_webhook_url" :
          rule.channel === "discord" ? "discord_webhook_url" : ""
        );
      if (!dest) continue;

      const key = `${rule.channel}:${dest}`;
      if (firedKeys.has(key)) continue;

      try {
        if (rule.channel === "slack") {
          await postWebhook(dest, slackPayload(event));
          firedKeys.add(key);
          logger.info({ tenantId: event.tenantId, ruleId: rule.id, channel: "slack" }, "Slack notification sent");
        } else if (rule.channel === "discord") {
          await postWebhook(dest, discordPayload(event));
          firedKeys.add(key);
          logger.info({ tenantId: event.tenantId, ruleId: rule.id, channel: "discord" }, "Discord notification sent");
        } else if (rule.channel === "email") {
          await sendEmail({ to: dest, subject: `[Sentinelware] ${event.title}`, html: alertEmailHtml(event) });
          firedKeys.add(key);
          logger.info({ tenantId: event.tenantId, ruleId: rule.id, channel: "email" }, "Alert email sent");
        }
      } catch (err) {
        logger.warn({ err, channel: rule.channel, ruleId: rule.id }, "Notification delivery failed");
      }
    }

    // Platform-level fallback webhooks (used if no per-rule destination matched)
    const [platformSlack, platformDiscord] = await Promise.all([
      getPlatformSetting("slack_webhook_url"),
      getPlatformSetting("discord_webhook_url"),
    ]);
    if (platformSlack && !firedKeys.has(`slack:${platformSlack}`)) {
      try {
        await postWebhook(platformSlack, slackPayload(event));
        logger.info({ tenantId: event.tenantId, channel: "slack" }, "Platform-level Slack notification sent");
      } catch (err) { logger.warn({ err }, "Platform Slack webhook failed"); }
    }
    if (platformDiscord && !firedKeys.has(`discord:${platformDiscord}`)) {
      try {
        await postWebhook(platformDiscord, discordPayload(event));
        logger.info({ tenantId: event.tenantId, channel: "discord" }, "Platform-level Discord notification sent");
      } catch (err) { logger.warn({ err }, "Platform Discord webhook failed"); }
    }
  } catch (err) {
    logger.error({ err, tenantId: event.tenantId }, "dispatchNotifications failed");
  }
}
