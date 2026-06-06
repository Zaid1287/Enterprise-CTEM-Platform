import { Resend } from "resend";

let resend: Resend | null = null;

function getResend(): Resend | null {
  if (!process.env.RESEND_API_KEY) return null;
  if (!resend) resend = new Resend(process.env.RESEND_API_KEY);
  return resend;
}

export interface EmailOptions {
  to: string;
  subject: string;
  html: string;
}

export async function sendEmail(opts: EmailOptions): Promise<void> {
  const client = getResend();
  if (!client) {
    // Dev mode: log to console
    console.log(`[Email] To: ${opts.to} | Subject: ${opts.subject}`);
    return;
  }
  await client.emails.send({
    from: "Sentinelware <noreply@sentinelware.io>",
    to: opts.to,
    subject: opts.subject,
    html: opts.html,
  });
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
