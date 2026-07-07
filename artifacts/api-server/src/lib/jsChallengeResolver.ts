/**
 * jsChallengeResolver.ts
 *
 * Puppeteer-based solver for JavaScript bot-check pages — Cloudflare "Just a
 * moment…", Akamai wait rooms, Imperva browser validation, and similar
 * challenge-response pages that require a real JS engine to pass.
 *
 * These challenges work by:
 *  1. Serving an HTML page that runs JavaScript to fingerprint the browser.
 *  2. Waiting for the script to complete (usually 2–5 s).
 *  3. Setting a bypass cookie (e.g. `cf_clearance`) and redirecting to the
 *     original page.
 *
 * A regular `fetch` call receives only the challenge HTML and can never proceed.
 * Puppeteer (headless Chrome) executes the JS, passes the fingerprint check,
 * and returns the final page content + all cookies set during the flow.
 *
 * NOT SOLVED HERE:
 *  - Visual/interactive CAPTCHAs (reCAPTCHA v2 checkbox, hCaptcha image grids,
 *    Turnstile interactive) — those require a human or a CAPTCHA solving API.
 *    See captchaSolver.ts for that.
 */

import { getBrowserInstance } from "./screenshotEngine.js";
import { logger } from "./logger.js";

const JS_CHALLENGE_TIMEOUT_MS = 30_000;

/** Markers that indicate a bot-check page is still active */
const CHALLENGE_TITLE_PATTERNS = [
  /just a moment/i,
  /checking your browser/i,
  /please wait/i,
  /ddos protection by/i,
  /before you continue/i,
  /one more step/i,
  /attention required/i,
];

const CHALLENGE_BODY_PATTERNS = [
  /checking your browser before accessing/i,
  /enable javascript and cookies to continue/i,
  /ray id:/i,
  /cf-browser-verification/i,
  /cf_chl_prog/i,
  /jschl_answer/i,
  /are you a human/i,
];

function isChallengeActive(title: string, body: string): boolean {
  if (CHALLENGE_TITLE_PATTERNS.some(p => p.test(title))) return true;
  if (CHALLENGE_BODY_PATTERNS.some(p => p.test(body))) return true;
  return false;
}

export interface JsChallengeResult {
  body: string;
  cookies: string;
  statusCode: number;
  challengeCleared: boolean;
}

/**
 * Attempt to resolve a JS challenge page using a headless browser.
 *
 * @param url       Full URL that returned a challenge page.
 * @param userAgent The User-Agent string from the matching HTTP fingerprint profile.
 * @param cookiesIn Semicolon-separated cookies from the existing CookieJar.
 * @returns Resolved page data on success, null if Puppeteer is unavailable or timed out.
 */
export async function resolveJsChallenge(
  url: string,
  userAgent?: string,
  cookiesIn?: string,
): Promise<JsChallengeResult | null> {
  let browser;
  try {
    browser = await getBrowserInstance();
  } catch (err) {
    logger.warn({ err, url }, "JS challenge resolver: Puppeteer unavailable — skipping");
    return null;
  }

  const page = await browser.newPage().catch(() => null);
  if (!page) return null;

  try {
    // Mirror the UA from the HTTP fingerprint profile so the browser
    // fingerprint matches what the target already saw in headers
    const ua = userAgent ?? "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
    await page.setUserAgent(ua);

    // Inject any session cookies already collected by the CookieJar
    if (cookiesIn && cookiesIn.trim()) {
      const parsed = new URL(url);
      const cookiePairs = cookiesIn.split(";").map(s => s.trim()).filter(Boolean);
      for (const pair of cookiePairs) {
        const eqIdx = pair.indexOf("=");
        if (eqIdx === -1) continue;
        const name  = pair.slice(0, eqIdx).trim();
        const value = pair.slice(eqIdx + 1).trim();
        if (!name) continue;
        await page.setCookie({ name, value, domain: parsed.hostname, path: "/" }).catch(() => {});
      }
    }

    // Navigate to the challenge URL
    const navResponse = await page.goto(url, {
      waitUntil: "domcontentloaded",
      timeout: JS_CHALLENGE_TIMEOUT_MS,
    }).catch(() => null);

    const initialStatusCode = navResponse?.status() ?? 0;

    // Wait for the challenge to clear — either the title changes from a known
    // challenge string, or we detect the page is no longer a bot-check page.
    // We poll every 500 ms for up to the challenge timeout.
    const challengeClearDeadline = Date.now() + 25_000;
    let challengeCleared = false;

    while (Date.now() < challengeClearDeadline) {
      const title = await page.title().catch(() => "");
      const body  = await (page.evaluate as any)("document.body ? document.body.textContent || '' : ''").catch(() => "");
      if (!isChallengeActive(title, body)) {
        challengeCleared = true;
        break;
      }
      await new Promise(r => setTimeout(r, 500));
    }

    // Capture final page state regardless of whether challenge cleared
    const finalBody   = await page.content().catch(() => "");
    const finalTitle  = await page.title().catch(() => "");
    const finalStatus = navResponse?.status() ?? 200;

    if (!challengeCleared) {
      logger.debug({ url, finalTitle }, "JS challenge resolver: challenge still active after timeout");
    } else {
      logger.debug({ url, finalTitle }, "JS challenge resolver: challenge cleared");
    }

    // Harvest all cookies (including the bypass cookie, e.g. cf_clearance)
    const pageCookies = await page.cookies().catch(() => []);
    const cookieStr   = pageCookies.map(c => `${c.name}=${c.value}`).join("; ");

    return {
      body: finalBody,
      cookies: cookieStr,
      statusCode: challengeCleared ? 200 : initialStatusCode,
      challengeCleared,
    };
  } catch (err) {
    logger.warn({ err, url }, "JS challenge resolver: error during Puppeteer navigation");
    return null;
  } finally {
    await page.close().catch(() => {});
  }
}
