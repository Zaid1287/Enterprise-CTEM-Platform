/**
 * jsChallengeResolver.ts
 *
 * Puppeteer-based solver for JavaScript bot-check pages — Cloudflare "Just a
 * moment…", Akamai wait rooms, Imperva browser validation, and similar
 * challenge-response pages that require a real JS engine to pass.
 *
 * STEALTH MEASURES
 *  Every new page has `evaluateOnNewDocument` hooks injected BEFORE navigation
 *  to hide the `navigator.webdriver` flag and emulate a real Chrome install.
 *  Without this Cloudflare detects headless Chrome and presents a harder
 *  interactive challenge or blocks outright.
 *
 *  All browser-context callbacks use `(globalThis as any)` for DOM globals
 *  (window, document, navigator) because the Node.js tsconfig does not include
 *  the DOM lib.  These callbacks execute inside Chromium, not Node.js.
 *
 * CAPTCHA TOKEN INJECTION (resolveWithCaptchaToken)
 *  After a CAPTCHA solver API (2captcha / CapMonster) returns a token, this
 *  module uses Puppeteer to inject it directly into the challenge page and
 *  trigger the form submission.  This is the ONLY correct method for Cloudflare
 *  Turnstile — HTTP header injection does not work for CF challenges.
 */

import { getBrowserInstance } from "./screenshotEngine.js";
import { logger } from "./logger.js";
import type { CaptchaType } from "./captchaSolver.js";

const JS_CHALLENGE_TIMEOUT_MS   = 30_000;
const CAPTCHA_INJECT_TIMEOUT_MS = 20_000;

// ── Challenge detection ────────────────────────────────────────────────────────

const CHALLENGE_TITLE_PATTERNS = [
  /just a moment/i,
  /checking your browser/i,
  /please wait/i,
  /ddos protection by/i,
  /before you continue/i,
  /one more step/i,
  /attention required/i,
  /security check/i,
];

const CHALLENGE_BODY_PATTERNS = [
  /checking your browser before accessing/i,
  /enable javascript and cookies to continue/i,
  /ray id:/i,
  /cf-browser-verification/i,
  /cf_chl_prog/i,
  /jschl_answer/i,
  /are you a human/i,
  /challenge-form/i,
  /cdn-cgi\/challenge-platform/i,
];

function isChallengeActive(title: string, body: string): boolean {
  if (CHALLENGE_TITLE_PATTERNS.some(p => p.test(title))) return true;
  if (CHALLENGE_BODY_PATTERNS.some(p => p.test(body))) return true;
  return false;
}

// ── Stealth injection ──────────────────────────────────────────────────────────

/**
 * Inject stealth overrides BEFORE any navigation so Cloudflare's fingerprinting
 * JS cannot detect headless Chrome.
 *
 * All DOM globals are accessed as `(globalThis as any).X` because the Node.js
 * tsconfig does not include the DOM lib — these overrides execute inside
 * Chromium where window/navigator/document are always available.
 */
async function applyStealthMeasures(page: any): Promise<void> {
  await page.evaluateOnNewDocument((() => {
    const win = globalThis as any;
    const nav = (globalThis as any).navigator as any;

    // 1. Hide automation flag — first thing every WAF checks
    Object.defineProperty(nav, "webdriver", {
      get: () => false,
      configurable: true,
    });

    // 2. Emulate Chrome's runtime object (undefined in headless Chrome)
    if (!win.chrome) {
      win.chrome = {
        runtime:   {},
        loadTimes: () => ({}),
        csi:       () => ({}),
        app:       { isInstalled: false, InstallState: {}, RunningState: {} },
      };
    }

    // 3. Non-empty plugin list (real Chrome has 3 plugins; headless has 0)
    const fakePlugins: any[] = [
      { name: "Chrome PDF Plugin",  filename: "internal-pdf-viewer",            description: "Portable Document Format" },
      { name: "Chrome PDF Viewer",  filename: "mhjfbmdgcfjbbpaeojofohoefgiehjai", description: "" },
      { name: "Native Client",      filename: "internal-nacl-plugin",           description: "" },
    ];
    (fakePlugins as any).refresh   = () => {};
    (fakePlugins as any).item      = (i: number) => fakePlugins[i] ?? null;
    (fakePlugins as any).namedItem = (n: string) => fakePlugins.find((p: any) => p.name === n) ?? null;
    Object.defineProperty(nav, "plugins",   { get: () => fakePlugins, configurable: true });
    Object.defineProperty(nav, "mimeTypes", { get: () => [],           configurable: true });

    // 4. Language list — sometimes empty in headless
    Object.defineProperty(nav, "languages", { get: () => ["en-US", "en"], configurable: true });

    // 5. Permissions API — headless returns "denied" for all; real Chrome varies
    if (nav.permissions?.query) {
      const origQuery = nav.permissions.query.bind(nav.permissions);
      nav.permissions.query = (params: any) =>
        params?.name === "notifications"
          ? Promise.resolve({ state: "default", onchange: null })
          : origQuery(params);
    }
  }) as any).catch(() => {});
}

// ── Shared cookie injection ────────────────────────────────────────────────────

async function injectCookies(page: any, url: string, cookiesIn: string | undefined): Promise<void> {
  if (!cookiesIn?.trim()) return;
  try {
    const { hostname } = new URL(url);
    for (const pair of cookiesIn.split(";").map(s => s.trim()).filter(Boolean)) {
      const eqIdx = pair.indexOf("=");
      if (eqIdx === -1) continue;
      const name  = pair.slice(0, eqIdx).trim();
      const value = pair.slice(eqIdx + 1).trim();
      if (name) await page.setCookie({ name, value, domain: hostname, path: "/" }).catch(() => {});
    }
  } catch { /* invalid URL */ }
}

// ── Public types ───────────────────────────────────────────────────────────────

export interface JsChallengeResult {
  body: string;
  cookies: string;
  statusCode: number;
  challengeCleared: boolean;
}

// ── JS Challenge Resolution ────────────────────────────────────────────────────

/**
 * Attempt to resolve a JS challenge page using a headless browser.
 *
 * Stealth measures are applied before navigation so Cloudflare's fingerprinting
 * JS does not detect headless Chrome.  We poll until the title/body no longer
 * match challenge patterns (challenge cleared) or the 25 s deadline passes.
 *
 * @param url       Full URL that returned a challenge page.
 * @param userAgent The User-Agent string from the matching HTTP fingerprint profile.
 * @param cookiesIn Semicolon-separated cookies from the existing CookieJar.
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
    // Apply stealth measures BEFORE navigation — must be first
    await applyStealthMeasures(page);

    const ua = userAgent ?? "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
    await page.setUserAgent(ua);

    // Inject any session cookies already collected by the CookieJar
    await injectCookies(page, url, cookiesIn);

    // Navigate; domcontentloaded fires when challenge page HTML is parsed —
    // our polling loop then waits for the challenge JS to redirect to the real page.
    const navResponse = await page.goto(url, {
      waitUntil: "domcontentloaded",
      timeout:   JS_CHALLENGE_TIMEOUT_MS,
    }).catch(() => null);

    const initialStatusCode = navResponse?.status() ?? 0;

    // Poll every 500 ms for up to 25 s for the challenge to clear
    const deadline = Date.now() + 25_000;
    let challengeCleared = false;

    while (Date.now() < deadline) {
      const title = await page.title().catch(() => "");
      // Access document via globalThis to avoid Node.js DOM-lib typecheck error
      const body = await (page.evaluate as any)(
        () => (globalThis as any).document?.body?.textContent ?? ""
      ).catch(() => "") as string;

      if (!isChallengeActive(title, body)) {
        challengeCleared = true;
        break;
      }
      await new Promise(r => setTimeout(r, 500));
    }

    const finalBody  = await page.content().catch(() => "");
    const finalTitle = await page.title().catch(() => "");

    if (!challengeCleared) {
      logger.debug({ url, finalTitle }, "JS challenge resolver: challenge still active after timeout");
    } else {
      logger.debug({ url, finalTitle }, "JS challenge resolver: challenge cleared");
    }

    // Harvest ALL cookies — bypass cookies (cf_clearance etc.) are in here
    const pageCookies = await page.cookies().catch(() => []);
    const cookieStr   = (pageCookies as any[]).map(c => `${c.name}=${c.value}`).join("; ");

    return {
      body:             finalBody,
      cookies:          cookieStr,
      statusCode:       challengeCleared ? 200 : initialStatusCode,
      challengeCleared,
    };
  } catch (err) {
    logger.warn({ err, url }, "JS challenge resolver: error during Puppeteer navigation");
    return null;
  } finally {
    await page.close().catch(() => {});
  }
}

// ── CAPTCHA Token Injection ────────────────────────────────────────────────────

/**
 * After a CAPTCHA solver API (2captcha / CapMonster) returns a token, use
 * Puppeteer to inject that token directly into the challenge page and trigger
 * the form submission / callback.
 *
 * This is the CORRECT method for Cloudflare Turnstile — simply adding the token
 * as an HTTP header to a GET request does NOT work.  Cloudflare requires the
 * token to be submitted to the challenge form, after which it sets the
 * `cf_clearance` cookie for all subsequent requests.
 *
 * Injection strategy per CAPTCHA type:
 *
 *  Turnstile    — fill `[name="cf-turnstile-response"]` hidden inputs +
 *                 call internal Turnstile success callback (if available) +
 *                 submit `#challenge-form`
 *
 *  reCAPTCHA v2 — fill `#g-recaptcha-response` textarea + call data-callback +
 *                 trigger ___grecaptcha_cfg internal clients
 *
 *  reCAPTCHA v3 — same submission path as v2
 *
 *  hCaptcha     — fill `[name="h-captcha-response"]` + call data-callback +
 *                 try hcaptcha.submit() API if available
 */
export async function resolveWithCaptchaToken(
  url: string,
  solved: { token: string; type: CaptchaType },
  userAgent?: string,
  cookiesIn?: string,
): Promise<JsChallengeResult | null> {
  let browser;
  try {
    browser = await getBrowserInstance();
  } catch (err) {
    logger.warn({ err, url }, "CAPTCHA token injector: Puppeteer unavailable");
    return null;
  }

  const page = await browser.newPage().catch(() => null);
  if (!page) return null;

  try {
    await applyStealthMeasures(page);

    const ua = userAgent ?? "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
    await page.setUserAgent(ua);
    await injectCookies(page, url, cookiesIn);

    // Navigate to the challenge page so the CAPTCHA widget is rendered
    await page.goto(url, {
      waitUntil: "domcontentloaded",
      timeout:   JS_CHALLENGE_TIMEOUT_MS,
    }).catch(() => null);

    // Give the page a moment to load CAPTCHA scripts before injecting
    await new Promise(r => setTimeout(r, 1_500));

    // Inject the token based on CAPTCHA type.
    // All DOM references use (globalThis as any) to avoid Node.js DOM-lib errors.
    const { type, token } = solved;
    await (page.evaluate as any)(
      ({ type, token }: { type: string; token: string }) => {
        const win = globalThis as any;
        const doc = (globalThis as any).document as any;

        if (type === "turnstile") {
          // ── Cloudflare Turnstile ──────────────────────────────────────────
          // 1. Fill hidden response inputs
          const inputs = doc.querySelectorAll(
            'input[name="cf-turnstile-response"], [name="cf_scalarchallenge_token"]'
          );
          inputs.forEach((el: any) => { el.value = token; });

          // 2. Call the internal Turnstile success callback if available
          const cfCallback =
            win.__cfTurnstileCallback ??
            win.__cf_chl_ctx?.chlCb ??
            win.__cf_chl_opt?.chlCb;
          if (typeof cfCallback === "function") cfCallback(token);

          // 3. Submit the Cloudflare challenge form (most reliable path)
          const form =
            doc.getElementById("challenge-form") ??
            doc.querySelector("form[action*='cdn-cgi']") ??
            doc.querySelector("form[action*='challenge-platform']");
          if (form) {
            const hiddenInput = form.querySelector('[name="cf-turnstile-response"]');
            if (hiddenInput) hiddenInput.value = token;
            form.submit();
          }

        } else if (type === "recaptcha_v2" || type === "recaptcha_v3") {
          // ── reCAPTCHA v2 / v3 ────────────────────────────────────────────
          // 1. Fill all g-recaptcha-response textareas
          const textareas = doc.querySelectorAll(
            '#g-recaptcha-response, [name="g-recaptcha-response"]'
          );
          textareas.forEach((el: any) => {
            el.innerHTML     = token;
            el.value         = token;
            el.style.display = "block";
          });

          // 2. Fire data-callback on .g-recaptcha wrapper
          const wrapper = doc.querySelector(".g-recaptcha, [data-callback]");
          const cbName  = wrapper?.getAttribute("data-callback");
          if (cbName && typeof win[cbName] === "function") win[cbName](token);

          // 3. Trigger internal ___grecaptcha_cfg clients
          if (win.___grecaptcha_cfg?.clients) {
            Object.values(win.___grecaptcha_cfg.clients).forEach((client: any) => {
              const cb = client?.callback ?? client?.l?.callback;
              if (typeof cb === "function") cb(token);
            });
          }

        } else if (type === "hcaptcha") {
          // ── hCaptcha ─────────────────────────────────────────────────────
          // 1. Fill h-captcha-response inputs
          const inputs = doc.querySelectorAll('[name="h-captcha-response"]');
          inputs.forEach((el: any) => { el.value = token; });

          // 2. Fire data-callback on .h-captcha wrapper
          const wrapper = doc.querySelector(".h-captcha, [data-callback]");
          const cbName  = wrapper?.getAttribute("data-callback");
          if (cbName && typeof win[cbName] === "function") win[cbName](token);

          // 3. Try hcaptcha.submit() if the API is loaded
          if (typeof win.hcaptcha?.submit === "function") {
            win.hcaptcha.submit(win.hcaptcha.getWidgetID?.() ?? "");
          }
        }
      },
      { type, token }
    ).catch((e: any) => {
      logger.debug(
        { url, captchaType: type, err: e?.message },
        "CAPTCHA token injector: page.evaluate error (non-fatal)"
      );
    });

    // Poll for challenge to clear / redirect to real content
    const deadline = Date.now() + CAPTCHA_INJECT_TIMEOUT_MS;
    let challengeCleared = false;

    while (Date.now() < deadline) {
      const title = await page.title().catch(() => "");
      const body  = await (page.evaluate as any)(
        () => (globalThis as any).document?.body?.textContent ?? ""
      ).catch(() => "") as string;

      if (!isChallengeActive(title, body)) {
        challengeCleared = true;
        break;
      }
      await new Promise(r => setTimeout(r, 500));
    }

    const finalBody  = await page.content().catch(() => "");
    const pageCookies = await page.cookies().catch(() => []);
    const cookieStr   = (pageCookies as any[]).map(c => `${c.name}=${c.value}`).join("; ");

    logger.debug({ url, captchaType: type, challengeCleared }, "CAPTCHA token injector: complete");
    return { body: finalBody, cookies: cookieStr, statusCode: 200, challengeCleared };

  } catch (err) {
    logger.warn({ err, url }, "CAPTCHA token injector: Puppeteer error");
    return null;
  } finally {
    await page.close().catch(() => {});
  }
}
