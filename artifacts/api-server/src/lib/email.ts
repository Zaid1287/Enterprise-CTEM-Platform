import { Resend } from "resend";
import nodemailer from "nodemailer";
import { getPlatformSetting } from "../routes/platformSettings";

let resend: Resend | null = null;
let cachedKey: string | null = null;

async function getResendAsync(): Promise<Resend | null> {
  const key = process.env.RESEND_API_KEY || await getPlatformSetting("resend_api_key");
  if (!key) return null;
  if (!resend || key !== cachedKey) {
    resend = new Resend(key);
    cachedKey = key;
  }
  return resend;
}

async function getSMTPTransport(): Promise<{ transport: nodemailer.Transporter; from: string } | null> {
  const host = await getPlatformSetting("smtp_host");
  if (!host) return null;
  const portStr = await getPlatformSetting("smtp_port");
  const port = parseInt(portStr ?? "587", 10);
  const user = await getPlatformSetting("smtp_user");
  const pass = await getPlatformSetting("smtp_pass");
  const from = await getPlatformSetting("smtp_from") ?? `Sentinelware <noreply@${host}>`;
  const transport = nodemailer.createTransport({
    host,
    port,
    secure: port === 465,
    auth: user && pass ? { user, pass } : undefined,
    tls: { rejectUnauthorized: false },
  });
  return { transport, from };
}

export interface EmailOptions {
  to: string;
  subject: string;
  html: string;
}

export async function sendEmail(opts: EmailOptions): Promise<void> {
  const client = await getResendAsync();
  if (client) {
    await client.emails.send({
      from: "Sentinelware <noreply@sentinelware.io>",
      to: opts.to,
      subject: opts.subject,
      html: opts.html,
    });
    return;
  }

  const smtp = await getSMTPTransport();
  if (smtp) {
    await smtp.transport.sendMail({
      from: smtp.from,
      to: opts.to,
      subject: opts.subject,
      html: opts.html,
    });
    return;
  }

  console.log(`[Email] No provider configured — To: ${opts.to} | Subject: ${opts.subject}`);
}

export function otpEmailHtml(opts: {
  title: string;
  otp: string;
  message: string;
  expiresMinutes?: number;
}): string {
  return `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8" />
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0a0a0a; color: #e5e5e5; margin: 0; padding: 40px 20px; }
    .container { max-width: 480px; margin: 0 auto; background: #111; border: 1px solid #222; border-radius: 12px; padding: 40px; }
    .brand { font-size: 18px; font-weight: 700; color: #fff; margin-bottom: 32px; letter-spacing: -0.5px; }
    h1 { font-size: 22px; font-weight: 700; margin: 0 0 8px; color: #fff; }
    p { font-size: 14px; color: #999; line-height: 1.6; margin: 0 0 24px; }
    .otp-box { background: #1a1a1a; border: 1px solid #333; border-radius: 10px; padding: 24px; text-align: center; margin: 24px 0; }
    .otp { font-size: 40px; font-weight: 800; letter-spacing: 10px; color: #7c3aed; font-family: monospace; }
    .expires { font-size: 12px; color: #666; margin-top: 8px; }
    .footer { font-size: 12px; color: #555; margin-top: 32px; padding-top: 24px; border-top: 1px solid #1e1e1e; }
  </style>
</head>
<body>
  <div class="container">
    <div class="brand">Sentinelware</div>
    <h1>${opts.title}</h1>
    <p>${opts.message}</p>
    <div class="otp-box">
      <div class="otp">${opts.otp}</div>
      ${opts.expiresMinutes ? `<div class="expires">Expires in ${opts.expiresMinutes} minutes</div>` : ""}
    </div>
    <p style="font-size:13px;">If you did not request this, you can safely ignore this email.</p>
    <div class="footer">
      &copy; ${new Date().getFullYear()} Sentinelware. All rights reserved.
    </div>
  </div>
</body>
</html>`;
}

export function verificationEmailHtml(opts: {
  assetName: string;
  domain: string;
  token: string;
  confirmUrl: string;
}): string {
  return `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8" />
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0a0a0a; color: #e5e5e5; margin: 0; padding: 40px 20px; }
    .container { max-width: 520px; margin: 0 auto; background: #111; border: 1px solid #222; border-radius: 12px; padding: 40px; }
    .brand { font-size: 18px; font-weight: 700; color: #fff; margin-bottom: 32px; }
    h1 { font-size: 22px; font-weight: 700; margin: 0 0 8px; color: #fff; }
    p { font-size: 14px; color: #999; line-height: 1.6; margin: 0 0 16px; }
    .asset-box { background: #1a1a1a; border: 1px solid #333; border-radius: 8px; padding: 16px; margin: 24px 0; font-family: monospace; font-size: 13px; color: #7c3aed; }
    .btn { display: inline-block; background: #7c3aed; color: #fff; text-decoration: none; padding: 14px 28px; border-radius: 8px; font-weight: 600; font-size: 15px; margin: 24px 0; }
    .footer { font-size: 12px; color: #555; margin-top: 32px; padding-top: 24px; border-top: 1px solid #1e1e1e; }
    .warning { font-size: 12px; color: #666; background: #1a1a1a; border-radius: 6px; padding: 12px; margin-top: 16px; }
  </style>
</head>
<body>
  <div class="container">
    <div class="brand">Sentinelware</div>
    <h1>Verify Asset Ownership</h1>
    <p>Someone has requested verification of the following asset in Sentinelware:</p>
    <div class="asset-box">${opts.assetName} &mdash; ${opts.domain}</div>
    <p>If you are the administrator of <strong>${opts.domain}</strong>, click the button below to confirm ownership. This link expires in 1 hour.</p>
    <a href="${opts.confirmUrl}" class="btn">Confirm Ownership &rarr;</a>
    <div class="warning">
      If you did not request this verification, you can safely ignore this email. No action is required.
    </div>
    <div class="footer">&copy; ${new Date().getFullYear()} Sentinelware. All rights reserved.</div>
  </div>
</body>
</html>`;
}

export interface AlertEmailEvent {
  title: string;
  message: string;
  severity: string;
  scanId?: number;
  findingsCount?: number;
  criticalCount?: number;
  highCount?: number;
  assetName?: string;
}

export function alertEmailHtml(event: AlertEmailEvent): string {
  const severityColor: Record<string, string> = {
    critical: "#ef4444", high: "#f97316", medium: "#eab308", low: "#22c55e", info: "#6b7280",
  };
  const color = severityColor[event.severity] ?? "#6b7280";
  const rows = [
    event.findingsCount !== undefined && `<tr><td style="color:#999;padding:6px 0;">Total Findings</td><td style="color:#fff;padding:6px 0;font-weight:600;">${event.findingsCount}</td></tr>`,
    event.criticalCount !== undefined && `<tr><td style="color:#999;padding:6px 0;">Critical</td><td style="color:#ef4444;padding:6px 0;font-weight:600;">${event.criticalCount}</td></tr>`,
    event.highCount !== undefined && event.highCount > 0 && `<tr><td style="color:#999;padding:6px 0;">High</td><td style="color:#f97316;padding:6px 0;font-weight:600;">${event.highCount}</td></tr>`,
    event.assetName && `<tr><td style="color:#999;padding:6px 0;">Asset</td><td style="color:#fff;padding:6px 0;">${event.assetName}</td></tr>`,
    event.scanId && `<tr><td style="color:#999;padding:6px 0;">Scan ID</td><td style="color:#fff;padding:6px 0;">#${event.scanId}</td></tr>`,
  ].filter(Boolean).join("");

  return `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8" />
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0a0a0a; color: #e5e5e5; margin: 0; padding: 40px 20px; }
    .container { max-width: 520px; margin: 0 auto; background: #111; border: 1px solid #222; border-radius: 12px; overflow: hidden; }
    .header { padding: 24px 32px; border-bottom: 1px solid #222; display: flex; align-items: center; gap: 12px; }
    .badge { display: inline-block; padding: 3px 10px; border-radius: 20px; font-size: 11px; font-weight: 700; letter-spacing: 0.5px; text-transform: uppercase; background: ${color}22; color: ${color}; border: 1px solid ${color}44; }
    .body { padding: 32px; }
    h2 { font-size: 20px; font-weight: 700; color: #fff; margin: 0 0 8px; }
    .message { font-size: 14px; color: #aaa; line-height: 1.6; margin: 0 0 24px; }
    table { width: 100%; border-collapse: collapse; }
    .footer { padding: 20px 32px; border-top: 1px solid #1e1e1e; font-size: 12px; color: #555; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <span style="font-size:16px;font-weight:700;color:#fff;">Sentinelware</span>
      <span class="badge">${event.severity.toUpperCase()}</span>
    </div>
    <div class="body">
      <h2>${event.title}</h2>
      <p class="message">${event.message}</p>
      ${rows ? `<table>${rows}</table>` : ""}
    </div>
    <div class="footer">
      Sentinelware CTEM &nbsp;&bull;&nbsp; ${new Date().toUTCString()}
    </div>
  </div>
</body>
</html>`;
}
