/**
 * captchaSolver.ts
 *
 * Automated CAPTCHA solving integration via 2captcha and CapMonster Cloud.
 *
 * Both services work by:
 *  1. Sending the CAPTCHA type + sitekey + page URL to a solver API.
 *  2. Receiving a task ID.
 *  3. Polling every 5 s until the solution (a token string) is ready.
 *  4. Injecting the token as a header or POST param in the retry request.
 *
 * CAPTCHA types supported:
 *  - reCAPTCHA v2 (checkbox / invisible)
 *  - reCAPTCHA v3 (score-based)
 *  - hCaptcha
 *  - Cloudflare Turnstile
 *
 * Configuration (stored in platform_settings table):
 *  captcha_solver_service  — "2captcha" | "capmonster" (default: "2captcha")
 *  captcha_solver_api_key  — API key for the selected service
 *
 * Pricing reference (as of 2024):
 *  2captcha:   https://2captcha.com  — ~$2.99/1000 hCaptcha solves
 *  CapMonster: https://capmonster.cloud — ~$0.60/1000 reCAPTCHA v2 solves
 */

import { getPlatformSetting } from "../routes/platformSettings.js";
import { logger } from "./logger.js";

export type CaptchaType = "recaptcha_v2" | "recaptcha_v3" | "hcaptcha" | "turnstile";
export type SolverService = "2captcha" | "capmonster";

export interface CaptchaInfo {
  type: CaptchaType;
  siteKey: string;
}

// ── Extract CAPTCHA info from a response body ──────────────────────────────────

const RECAPTCHA_SITEKEY_RE = /data-sitekey=["']([A-Za-z0-9_\-]{30,})["']/;
const HCAPTCHA_JS_RE       = /hcaptcha\.com\/1\/api\.js/i;
const HCAPTCHA_SITEKEY_RE  = /data-sitekey=["']([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})["']/i;
const TURNSTILE_JS_RE      = /challenges\.cloudflare\.com\/turnstile/i;
const TURNSTILE_SITEKEY_RE = /data-sitekey=["'](0x[A-Za-z0-9]+)["']/;
const RECAPTCHA_V3_RE      = /grecaptcha\.execute\(["']([A-Za-z0-9_\-]{30,})["']/;

export function extractCaptchaInfo(body: string, _pageUrl: string): CaptchaInfo | null {
  // Cloudflare Turnstile (sitekey always starts with 0x)
  if (TURNSTILE_JS_RE.test(body)) {
    const m = body.match(TURNSTILE_SITEKEY_RE);
    if (m) return { type: "turnstile", siteKey: m[1]! };
  }

  // hCaptcha (UUID-format sitekey)
  if (HCAPTCHA_JS_RE.test(body)) {
    const m = body.match(HCAPTCHA_SITEKEY_RE);
    if (m) return { type: "hcaptcha", siteKey: m[1]! };
  }

  // reCAPTCHA v3 (grecaptcha.execute call with inline sitekey)
  const v3Match = body.match(RECAPTCHA_V3_RE);
  if (v3Match) return { type: "recaptcha_v3", siteKey: v3Match[1]! };

  // reCAPTCHA v2 (data-sitekey on a div; long alphanumeric key)
  if (body.includes("recaptcha") || body.includes("grecaptcha")) {
    const m = body.match(RECAPTCHA_SITEKEY_RE);
    if (m) return { type: "recaptcha_v2", siteKey: m[1]! };
  }

  return null;
}

// ── 2captcha ──────────────────────────────────────────────────────────────────

async function submit2captcha(info: CaptchaInfo, pageUrl: string, apiKey: string): Promise<string> {
  const base = "https://2captcha.com";
  let method: string;
  let extraParams: Record<string, string> = {};

  switch (info.type) {
    case "hcaptcha":
      method = "hcaptcha";
      break;
    case "turnstile":
      method = "turnstile";
      break;
    case "recaptcha_v3":
      method = "userrecaptcha";
      extraParams = { version: "v3", min_score: "0.3" };
      break;
    default:
      method = "userrecaptcha";
  }

  const params = new URLSearchParams({
    key:      apiKey,
    method,
    sitekey:  info.siteKey,
    pageurl:  pageUrl,
    json:     "1",
    ...extraParams,
  });

  const res  = await fetch(`${base}/in.php`, { method: "POST", body: params });
  const json = await res.json() as any;
  if (json.status !== 1) throw new Error(`2captcha submit failed: ${json.error_text ?? json.request}`);
  return String(json.request); // task ID
}

async function poll2captcha(taskId: string, apiKey: string): Promise<string> {
  const base = "https://2captcha.com";
  const MAX_POLLS = 24; // 24 × 5 s = 2 min max

  for (let i = 0; i < MAX_POLLS; i++) {
    await new Promise(r => setTimeout(r, 5_000));
    const params = new URLSearchParams({ key: apiKey, action: "get", id: taskId, json: "1" });
    const res  = await fetch(`${base}/res.php?${params}`);
    const json = await res.json() as any;

    if (json.status === 1) return String(json.request); // solved token
    if (json.request !== "CAPCHA_NOT_READY") {
      throw new Error(`2captcha poll failed: ${json.request}`);
    }
  }
  throw new Error("2captcha: solution timed out (2 min)");
}

// ── CapMonster Cloud ──────────────────────────────────────────────────────────

type CapMonsterTaskType =
  | "HCaptchaTaskProxyless"
  | "TurnstileTaskProxyless"
  | "RecaptchaV2TaskProxyless"
  | "RecaptchaV3TaskProxyless";

function capMonsterTaskType(info: CaptchaInfo): CapMonsterTaskType {
  switch (info.type) {
    case "hcaptcha":    return "HCaptchaTaskProxyless";
    case "turnstile":   return "TurnstileTaskProxyless";
    case "recaptcha_v3": return "RecaptchaV3TaskProxyless";
    default:             return "RecaptchaV2TaskProxyless";
  }
}

async function submitCapmonster(info: CaptchaInfo, pageUrl: string, apiKey: string): Promise<number> {
  const body = {
    clientKey: apiKey,
    task: {
      type:       capMonsterTaskType(info),
      websiteURL: pageUrl,
      websiteKey: info.siteKey,
      ...(info.type === "recaptcha_v3" ? { minScore: 0.3 } : {}),
    },
  };

  const res  = await fetch("https://api.capmonster.cloud/createTask", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const json = await res.json() as any;
  if (json.errorId !== 0) throw new Error(`CapMonster submit failed: ${json.errorDescription}`);
  return Number(json.taskId);
}

async function pollCapmonster(taskId: number, apiKey: string): Promise<string> {
  const MAX_POLLS = 24;
  for (let i = 0; i < MAX_POLLS; i++) {
    await new Promise(r => setTimeout(r, 5_000));
    const res  = await fetch("https://api.capmonster.cloud/getTaskResult", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ clientKey: apiKey, taskId }),
    });
    const json = await res.json() as any;
    if (json.errorId !== 0) throw new Error(`CapMonster poll failed: ${json.errorDescription}`);
    if (json.status === "ready") {
      return String(json.solution?.gRecaptchaResponse ?? json.solution?.token ?? "");
    }
  }
  throw new Error("CapMonster: solution timed out (2 min)");
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Attempt to automatically solve the CAPTCHA found in `body`.
 * Returns the solved token string on success, null if no service is configured
 * or CAPTCHA info cannot be extracted.
 *
 * The returned token should be injected as:
 *   - reCAPTCHA v2/v3:  `g-recaptcha-response` POST field / header
 *   - hCaptcha:         `h-captcha-response` POST field / header
 *   - Turnstile:        `cf-turnstile-response` POST field / header
 */
export async function trySolveCaptcha(
  body: string,
  pageUrl: string,
): Promise<{ token: string; type: CaptchaType } | null> {
  const info = extractCaptchaInfo(body, pageUrl);
  if (!info) {
    logger.debug({ pageUrl }, "CAPTCHA solver: no recognisable CAPTCHA found in body");
    return null;
  }

  const [service, apiKey] = await Promise.all([
    getPlatformSetting("captcha_solver_service"),
    getPlatformSetting("captcha_solver_api_key"),
  ]);

  if (!apiKey) {
    logger.debug({ pageUrl, captchaType: info.type }, "CAPTCHA solver: no API key configured (set captcha_solver_api_key in Platform Settings)");
    return null;
  }

  const svc: SolverService = (service === "capmonster") ? "capmonster" : "2captcha";
  logger.info({ pageUrl, captchaType: info.type, siteKey: info.siteKey.slice(0, 12) + "…", service: svc }, "CAPTCHA solver: submitting task");

  try {
    let token: string;
    if (svc === "capmonster") {
      const taskId = await submitCapmonster(info, pageUrl, apiKey);
      token = await pollCapmonster(taskId, apiKey);
    } else {
      const taskId = await submit2captcha(info, pageUrl, apiKey);
      token = await poll2captcha(taskId, apiKey);
    }

    if (!token) throw new Error("Solver returned empty token");

    logger.info({ pageUrl, captchaType: info.type, service: svc, tokenLen: token.length }, "CAPTCHA solver: task solved");
    return { token, type: info.type };
  } catch (err) {
    logger.warn({ err, pageUrl, captchaType: info.type, service: svc }, "CAPTCHA solver: failed");
    return null;
  }
}

/**
 * Build the request header name that carries the CAPTCHA solution token.
 * Targets that accept `fetch`-based re-submission look for these headers.
 */
export function captchaTokenHeader(type: CaptchaType): string {
  switch (type) {
    case "hcaptcha":               return "x-hcaptcha-response";
    case "turnstile":              return "cf-turnstile-response";
    case "recaptcha_v3":
    case "recaptcha_v2":
    default:                       return "x-recaptcha-response";
  }
}
