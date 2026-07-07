export type ResponseClassification =
  | "Success"
  | "Redirect"
  | "RateLimited"
  | "Forbidden"
  | "Captcha"
  | "TemporaryError"
  | "PermanentError"
  | "CloudflareChallenge"
  | "AkamaiChallenge"
  | "ImpervaBlock"
  | "Timeout"
  | "TLSError"
  | "ConnectionReset";

export interface AnalyzedResponse {
  classification: ResponseClassification;
  wafDetected: boolean;
  captchaDetected: boolean;
  isTransient: boolean;
  isSuccess: boolean;
  retryAfterMs?: number;
}

const WAF_BODY_PATTERNS = [
  /cloudflare/i,
  /attention required/i,
  /ray id:/i,
  /akamai/i,
  /imperva/i,
  /incapsula/i,
  /sucuri/i,
  /perimeterx/i,
  /fortigate/i,
  /barracuda/i,
  /__cfduid/i,
  /cf-ray/i,
  /access denied.*waf/i,
  /blocked by/i,
  /security check/i,
];

const CAPTCHA_BODY_PATTERNS = [
  /captcha/i,
  /hcaptcha/i,
  /recaptcha/i,
  /turnstile/i,
  /are you a robot/i,
  /please verify you are human/i,
  /i'm not a robot/i,
  /challenge.*required/i,
];

const CF_HEADERS = ["cf-ray", "cf-cache-status", "__cfduid", "cf-mitigated"];
const AKAMAI_HEADERS = ["x-akamai", "x-check-cacheable", "akamai-origin-hop"];
const IMPERVA_HEADERS = ["x-iinfo", "visid_incap"];

function detectWaf(status: number, body: string, headers: Record<string, string>): boolean {
  if (CF_HEADERS.some(h => headers[h])) return true;
  if (AKAMAI_HEADERS.some(h => headers[h])) return true;
  if (IMPERVA_HEADERS.some(h => headers[h])) return true;
  if ([403, 406, 429, 503].includes(status) && WAF_BODY_PATTERNS.some(p => p.test(body.slice(0, 4000)))) return true;
  return false;
}

function detectCaptcha(body: string): boolean {
  return CAPTCHA_BODY_PATTERNS.some(p => p.test(body.slice(0, 4000)));
}

function parseRetryAfter(headerValue: string | undefined): number | undefined {
  if (!headerValue) return undefined;
  const secs = parseInt(headerValue, 10);
  if (!isNaN(secs)) return secs * 1_000;
  const date = new Date(headerValue);
  if (!isNaN(date.getTime())) return Math.max(0, date.getTime() - Date.now());
  return undefined;
}

export function analyzeResponse(
  status: number,
  body: string,
  headers: Record<string, string>,
  errorName?: string,
): AnalyzedResponse {
  const wafDetected     = detectWaf(status, body, headers);
  const captchaDetected = detectCaptcha(body);

  if (errorName === "AbortError" || errorName === "TimeoutError") {
    return { classification: "Timeout", wafDetected, captchaDetected, isTransient: true, isSuccess: false };
  }
  if (errorName === "ConnectionReset" || errorName === "ECONNRESET") {
    return { classification: "ConnectionReset", wafDetected, captchaDetected, isTransient: true, isSuccess: false };
  }
  if (errorName?.includes("TLS") || errorName?.includes("SSL") || errorName?.includes("CERT")) {
    return { classification: "TLSError", wafDetected, captchaDetected, isTransient: false, isSuccess: false };
  }

  if (status === 0) {
    return { classification: "ConnectionReset", wafDetected, captchaDetected, isTransient: true, isSuccess: false };
  }

  if (status >= 200 && status < 300) {
    return { classification: "Success", wafDetected, captchaDetected, isTransient: false, isSuccess: true };
  }

  if (status >= 300 && status < 400) {
    return { classification: "Redirect", wafDetected, captchaDetected, isTransient: false, isSuccess: true };
  }

  if (status === 429) {
    const retryAfterMs = parseRetryAfter(headers["retry-after"]);
    return { classification: "RateLimited", wafDetected, captchaDetected, isTransient: true, isSuccess: false, retryAfterMs };
  }

  if (status === 403) {
    if (wafDetected) {
      if (CF_HEADERS.some(h => headers[h]) || /cloudflare/i.test(body.slice(0, 4000))) {
        return { classification: "CloudflareChallenge", wafDetected, captchaDetected, isTransient: true, isSuccess: false };
      }
      if (AKAMAI_HEADERS.some(h => headers[h])) {
        return { classification: "AkamaiChallenge", wafDetected, captchaDetected, isTransient: true, isSuccess: false };
      }
      if (IMPERVA_HEADERS.some(h => headers[h])) {
        return { classification: "ImpervaBlock", wafDetected, captchaDetected, isTransient: true, isSuccess: false };
      }
    }
    if (captchaDetected) {
      return { classification: "Captcha", wafDetected, captchaDetected, isTransient: true, isSuccess: false };
    }
    return { classification: "Forbidden", wafDetected, captchaDetected, isTransient: false, isSuccess: false };
  }

  if (status === 503 || status === 502 || status === 504) {
    return { classification: "TemporaryError", wafDetected, captchaDetected, isTransient: true, isSuccess: false };
  }

  if (status >= 500) {
    return { classification: "TemporaryError", wafDetected, captchaDetected, isTransient: true, isSuccess: false };
  }

  if (status >= 400) {
    return { classification: "PermanentError", wafDetected, captchaDetected, isTransient: false, isSuccess: false };
  }

  return { classification: "PermanentError", wafDetected, captchaDetected, isTransient: false, isSuccess: false };
}
