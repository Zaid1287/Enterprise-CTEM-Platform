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
  // Cloudflare
  /cloudflare/i,
  /attention required/i,
  /ray id:/i,
  /__cfduid/i,
  /cf-ray/i,
  /enable javascript and cookies/i,
  // Akamai
  /akamai/i,
  /reference.*#[0-9a-f]{2}\.[0-9a-f]+\.[0-9a-f]+/i,
  // Imperva / Incapsula
  /imperva/i,
  /incapsula/i,
  /incident id:/i,
  // Sucuri
  /sucuri/i,
  /website firewall/i,
  // PerimeterX
  /perimeterx/i,
  /px_uuid/i,
  // Fortinet / FortiGate
  /fortigate/i,
  /fortiwafd/i,
  // Barracuda
  /barracuda/i,
  // AWS WAF
  /aws waf/i,
  /request blocked.*aws/i,
  // F5 BIG-IP ASM
  /the requested url was rejected/i,
  /f5\s*networks/i,
  /bigipserver/i,
  /unauthorized.*big.?ip/i,
  // DDoS-Guard
  /ddos.guard/i,
  // Radware / AppWall
  /radware/i,
  /clipsecure/i,
  // ModSecurity / generic open-source WAFs
  /mod_security/i,
  /modsecurity/i,
  /not acceptable.*security/i,
  // Reblaze
  /reblaze/i,
  // Azure Front Door WAF
  /azure.*waf/i,
  /microsoft.*waf/i,
  // Generic
  /access denied.*waf/i,
  /blocked by/i,
  /security check/i,
  /your ip.*blocked/i,
  /suspicious activity detected/i,
  /automated.*access.*denied/i,
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
  /just a moment/i,
  /checking your browser/i,
  /browser.*checking/i,
  /ddos.*protection/i,
  /one more step/i,
];

const CF_HEADERS      = ["cf-ray", "cf-cache-status", "__cfduid", "cf-mitigated", "cf-connecting-ip"];
const AKAMAI_HEADERS  = ["x-akamai", "x-check-cacheable", "akamai-origin-hop", "x-akamai-transformed"];
const IMPERVA_HEADERS = ["x-iinfo", "visid_incap", "incap_ses"];
const AWS_WAF_HEADERS = ["x-amzn-waf-action", "x-amzn-trace-id"];
const F5_HEADERS      = ["x-wa-info", "x-cnection"];
const DDOS_GUARD_HEADERS = ["ddos-guard"];
const AZURE_HEADERS   = ["x-azure-ref", "x-fd-healthprobe"];
const RADWARE_HEADERS = ["x-sl-compstate"];
const REBLAZE_HEADERS = ["x-reblaze-protection"];

function detectWaf(status: number, body: string, headers: Record<string, string>): boolean {
  if (CF_HEADERS.some(h => headers[h])) return true;
  if (AKAMAI_HEADERS.some(h => headers[h])) return true;
  if (IMPERVA_HEADERS.some(h => headers[h])) return true;
  if (AWS_WAF_HEADERS.some(h => headers[h])) return true;
  if (F5_HEADERS.some(h => headers[h])) return true;
  if (DDOS_GUARD_HEADERS.some(h => headers[h])) return true;
  if (AZURE_HEADERS.some(h => headers[h])) return true;
  if (RADWARE_HEADERS.some(h => headers[h])) return true;
  if (REBLAZE_HEADERS.some(h => headers[h])) return true;
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
        return { classification: "CloudflareChallenge", wafDetected, captchaDetected, isTransient: false, isSuccess: false };
      }
      if (AKAMAI_HEADERS.some(h => headers[h])) {
        return { classification: "AkamaiChallenge", wafDetected, captchaDetected, isTransient: false, isSuccess: false };
      }
      if (IMPERVA_HEADERS.some(h => headers[h])) {
        return { classification: "ImpervaBlock", wafDetected, captchaDetected, isTransient: false, isSuccess: false };
      }
    }
    if (captchaDetected) {
      return { classification: "Captcha", wafDetected, captchaDetected, isTransient: false, isSuccess: false };
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
