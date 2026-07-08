/**
 * Unit tests for the 407 Proxy Authentication Required handling path in
 * orchestratedFetch (scanOrchestrator.ts).
 *
 * Coverage:
 *  1. 407 returned as an HTTP response → recordProxyOutcome("auth_failed") called,
 *     dispatchNotifications fired with correct tenantId + title, falls back to direct.
 *  2. 407 surfaced as a thrown Error → same contract as above.
 *  3. require_proxies=true + 407 response → throws instead of falling back.
 *  4. require_proxies=true + 407 thrown error → throws instead of falling back.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

// ── vi.hoisted: declare spy refs before any mock factory runs ─────────────────

const {
  recordProxyOutcomeMock,
  dispatchNotificationsMock,
  undiciFetchMock,
  configRowsRef,
  MOCK_PROXY,
} = vi.hoisted(() => {
  return {
    recordProxyOutcomeMock:    vi.fn<() => Promise<{ enteredCooldown: boolean }>>(),
    dispatchNotificationsMock: vi.fn<() => Promise<void>>(),
    undiciFetchMock:           vi.fn(),
    // Mutable ref: tests swap this to change config without re-mocking.
    configRowsRef: { current: [] as Array<{ key: string; value: string }> },
    MOCK_PROXY: {
      id:          99,
      ip:          "10.0.0.1",
      port:        3128,
      type:        "http",
      healthScore: 80,
      username:    "user",
      password:    "secret",
    },
  };
});

// ── @workspace/db mock ───────────────────────────────────────────────────────

vi.mock("@workspace/db", () => {
  // Sentinel objects for table identity checks inside from()
  const _orchCfgTable   = { _tag: "orchestrator_config" } as const;
  const _fpTable        = { _tag: "scan_fingerprint_profiles" } as const;
  const _telemetryTable = { _tag: "scan_request_telemetry" } as const;

  const makeThen = (val: unknown) => {
    const p: any = Promise.resolve(val);
    p.where   = () => Promise.resolve(val);
    p.orderBy = () => Promise.resolve(val);
    p.limit   = () => Promise.resolve(val);
    return p;
  };

  return {
    db: {
      select: (_fields?: unknown) => ({
        from: (table: unknown) => {
          if (table === _orchCfgTable) return makeThen(configRowsRef.current);
          return makeThen([]);
        },
      }),
      insert: (_table: unknown) => ({
        values: () => Promise.resolve(),
        onConflictDoUpdate: () => Promise.resolve(),
      }),
      update: (_table: unknown) => ({
        set: () => ({ where: () => Promise.resolve() }),
      }),
    },
    orchestratorConfigTable:       _orchCfgTable,
    scanFingerprintProfilesTable:  _fpTable,
    scanRequestTelemetryTable:     _telemetryTable,
  };
});

// ── drizzle-orm mock (eq / and / etc. are used by loadConfig) ────────────────

vi.mock("drizzle-orm", () => ({
  eq:      () => ({}),
  and:     () => ({}),
  or:      () => ({}),
  lt:      () => ({}),
  isNull:  () => ({}),
  sql:     () => ({}),
}));

// ── proxyManager mock ─────────────────────────────────────────────────────────

vi.mock("../proxyManager", () => ({
  selectHealthiestProxy: vi.fn().mockResolvedValue(MOCK_PROXY),
  recordProxyOutcome:    recordProxyOutcomeMock,
}));

// ── notifier mock ─────────────────────────────────────────────────────────────

vi.mock("../notifier", () => ({
  dispatchNotifications: dispatchNotificationsMock,
}));

// ── undici mock ───────────────────────────────────────────────────────────────
// ProxyAgent is used as a constructor; Agent is used as a constructor and type.
// We return plain objects so that the dispatcher arg is accepted by undiciFetch.

vi.mock("undici", () => {
  class MockAgent {}
  class MockProxyAgent extends MockAgent {}

  return {
    fetch:      undiciFetchMock,
    ProxyAgent: MockProxyAgent,
    Agent:      MockAgent,
  };
});

// ── delayEngine mock — no real sleeps ─────────────────────────────────────────

vi.mock("../delayEngine", () => ({
  getDelay:          () => 0,
  sleep:             () => Promise.resolve(),
  setDelayMultiplier: vi.fn(),
}));

// ── tlsFingerprintRotator mock ────────────────────────────────────────────────
// TLS_PROFILES is iterated at module-init to build _tlsDispatcherPool; return
// an empty array so no real TLS connections are attempted.

vi.mock("../tlsFingerprintRotator", () => {
  class MockAgent {}
  return {
    TLS_PROFILES:        [],
    buildTlsDispatcher:  () => new MockAgent(),
    buildSocksDispatcher: vi.fn().mockResolvedValue(new MockAgent()),
    getRandomTlsProfile: () => ({ id: "mock-tls" }),
  };
});

// ── remaining dependency stubs ────────────────────────────────────────────────

vi.mock("../tenantContext",        () => ({ getCurrentTenantId:    () => undefined }));
vi.mock("../scanIntensityContext", () => ({ getCurrentScanIntensity: () => undefined }));

vi.mock("../adaptiveRateLimiter", () => ({
  waitForRateLimitToken:    vi.fn(),
  recordRateLimitSuccess:   vi.fn(),
  recordRateLimitFailure:   vi.fn(),
}));

vi.mock("../circuitBreaker", () => ({
  getCircuitState:     () => "CLOSED",
  isCircuitOpen:       () => false,
  recordCircuitResult: vi.fn().mockResolvedValue({ justTripped: false }),
}));

vi.mock("../cookieJar", () => ({
  storeCookies:   vi.fn(),
  getCookieHeader: () => null,
}));

vi.mock("../responseAnalyzer", () => ({
  analyzeResponse: (_status: number) => ({
    isSuccess:        _status >= 200 && _status < 300,
    wafDetected:      false,
    captchaDetected:  false,
    classification:   _status >= 200 && _status < 300 ? "Success" : "PermanentError",
    retryAfterMs:     null,
  }),
}));

vi.mock("../dnsResolverPool", () => ({
  resolveWithRotation: vi.fn(),
}));

vi.mock("../sseManager", () => ({
  pushWaterfallEvent:         vi.fn(),
  pushWaterfallDegradedEvent: vi.fn(),
}));

vi.mock("../logger", () => ({
  logger: {
    info:  vi.fn(),
    warn:  vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  },
}));

vi.mock("../jsChallengeResolver", () => ({
  resolveJsChallenge:      vi.fn().mockResolvedValue(null),
  resolveWithCaptchaToken: vi.fn().mockResolvedValue(null),
}));

vi.mock("../captchaSolver", () => ({
  trySolveCaptcha:    vi.fn().mockResolvedValue(null),
  captchaTokenHeader: vi.fn().mockReturnValue("x-captcha-token"),
}));

// ── Helpers ───────────────────────────────────────────────────────────────────

function makeResponse(status: number, body = ""): Response {
  const headers = new Headers({ "content-type": "text/html" });
  return {
    status,
    ok:       status >= 200 && status < 300,
    headers,
    clone:    () => makeResponse(status, body),
    text:     () => Promise.resolve(body),
    json:     () => Promise.resolve({}),
    arrayBuffer: () => Promise.resolve(new ArrayBuffer(0)),
    body:     null,
    bodyUsed: false,
    url:      "",
    type:     "default",
    redirected: false,
    statusText: String(status),
    formData:   () => Promise.resolve(new FormData()),
    blob:       () => Promise.resolve(new Blob()),
  } as unknown as Response;
}

/** Base config rows: proxies enabled, require_proxies=false, max_retries=1 */
function baseConfigRows(overrides: Record<string, string> = {}): Array<{ key: string; value: string }> {
  return Object.entries({
    enabled:                "true",
    use_proxies:            "true",
    require_proxies:        "false",
    max_retries:            "1",
    rotate_fingerprints:    "false",
    log_all_requests:       "false",
    waf_bypass_strategy:    "none",
    adaptive_rate_limit:    "false",
    circuit_breaker_enabled:"false",
    proxy_health_scoring:   "false",
    retry_base_delay_ms:    "0",
    max_backoff_ms:         "0",
    ...overrides,
  }).map(([key, value]) => ({ key, value }));
}

// ── Import the module under test (after all mocks are registered) ──────────────

import { orchestratedFetch, invalidateConfigCache } from "../scanOrchestrator.js";

// ── Tests ─────────────────────────────────────────────────────────────────────

describe("orchestratedFetch — 407 Proxy Auth handling", () => {
  const TEST_URL     = "http://target.example.com/scan";
  const TEST_TENANT  = 7;
  const CTX          = { tenantId: TEST_TENANT, scanId: 10, assetId: 3, target: "target.example.com" };

  beforeEach(() => {
    vi.clearAllMocks();
    // Flush the per-tenant config cache so each test loads fresh config rows.
    invalidateConfigCache(TEST_TENANT);
    recordProxyOutcomeMock.mockResolvedValue({ enteredCooldown: false });
    dispatchNotificationsMock.mockResolvedValue(undefined);
  });

  // ── Path 1: 407 as HTTP response, require_proxies=false ───────────────────

  describe("407 returned as HTTP response (require_proxies=false)", () => {
    beforeEach(() => {
      configRowsRef.current = baseConfigRows();
    });

    it("calls recordProxyOutcome with 'auth_failed'", async () => {
      // First call → 407 via proxy; second call → 200 direct
      undiciFetchMock
        .mockResolvedValueOnce(makeResponse(407))
        .mockResolvedValueOnce(makeResponse(200));

      await orchestratedFetch(TEST_URL, {}, CTX);

      expect(recordProxyOutcomeMock).toHaveBeenCalledWith(MOCK_PROXY.id, "auth_failed");
    });

    it("calls dispatchNotifications with correct tenantId and 'Proxy Auth Failed' title", async () => {
      undiciFetchMock
        .mockResolvedValueOnce(makeResponse(407))
        .mockResolvedValueOnce(makeResponse(200));

      await orchestratedFetch(TEST_URL, {}, CTX);

      expect(dispatchNotificationsMock).toHaveBeenCalledWith(
        expect.objectContaining({
          tenantId: TEST_TENANT,
          title:    expect.stringContaining("Proxy Auth Failed"),
        }),
      );
    });

    it("does NOT throw when require_proxies=false — falls back to direct fetch", async () => {
      undiciFetchMock
        .mockResolvedValueOnce(makeResponse(407))
        .mockResolvedValueOnce(makeResponse(200));

      await expect(orchestratedFetch(TEST_URL, {}, CTX)).resolves.toBeDefined();
    });
  });

  // ── Path 2: 407 surfaced as a thrown Error, require_proxies=false ─────────

  describe("407 thrown as Error (require_proxies=false)", () => {
    beforeEach(() => {
      configRowsRef.current = baseConfigRows();
    });

    it("calls recordProxyOutcome with 'auth_failed'", async () => {
      undiciFetchMock
        .mockRejectedValueOnce(new Error("407 Proxy Authentication Required"))
        .mockResolvedValueOnce(makeResponse(200));

      await orchestratedFetch(TEST_URL, {}, CTX);

      expect(recordProxyOutcomeMock).toHaveBeenCalledWith(MOCK_PROXY.id, "auth_failed");
    });

    it("calls dispatchNotifications with correct tenantId and 'Proxy Auth Failed' title", async () => {
      undiciFetchMock
        .mockRejectedValueOnce(new Error("407 Proxy Authentication Required"))
        .mockResolvedValueOnce(makeResponse(200));

      await orchestratedFetch(TEST_URL, {}, CTX);

      expect(dispatchNotificationsMock).toHaveBeenCalledWith(
        expect.objectContaining({
          tenantId: TEST_TENANT,
          title:    expect.stringContaining("Proxy Auth Failed"),
        }),
      );
    });

    it("does NOT throw when require_proxies=false — falls back to direct fetch", async () => {
      undiciFetchMock
        .mockRejectedValueOnce(new Error("407 Proxy Authentication Required"))
        .mockResolvedValueOnce(makeResponse(200));

      await expect(orchestratedFetch(TEST_URL, {}, CTX)).resolves.toBeDefined();
    });
  });

  // ── Path 3: 407 as HTTP response, require_proxies=true ────────────────────

  describe("407 returned as HTTP response (require_proxies=true)", () => {
    beforeEach(() => {
      configRowsRef.current = baseConfigRows({ require_proxies: "true" });
    });

    it("calls recordProxyOutcome with 'auth_failed'", async () => {
      undiciFetchMock.mockResolvedValueOnce(makeResponse(407));

      await expect(orchestratedFetch(TEST_URL, {}, CTX)).rejects.toThrow();

      expect(recordProxyOutcomeMock).toHaveBeenCalledWith(MOCK_PROXY.id, "auth_failed");
    });

    it("calls dispatchNotifications before throwing", async () => {
      undiciFetchMock.mockResolvedValueOnce(makeResponse(407));

      await expect(orchestratedFetch(TEST_URL, {}, CTX)).rejects.toThrow();

      expect(dispatchNotificationsMock).toHaveBeenCalledWith(
        expect.objectContaining({
          tenantId: TEST_TENANT,
          title:    expect.stringContaining("Proxy Auth Failed"),
        }),
      );
    });

    it("throws instead of falling back to direct traffic", async () => {
      undiciFetchMock.mockResolvedValueOnce(makeResponse(407));

      await expect(orchestratedFetch(TEST_URL, {}, CTX)).rejects.toThrow(
        /require_proxies=true/,
      );
    });
  });

  // ── Path 4: 407 thrown as Error, require_proxies=true ────────────────────

  describe("407 thrown as Error (require_proxies=true)", () => {
    beforeEach(() => {
      configRowsRef.current = baseConfigRows({ require_proxies: "true" });
    });

    it("calls recordProxyOutcome with 'auth_failed'", async () => {
      undiciFetchMock.mockRejectedValueOnce(new Error("407 Proxy Authentication Required"));

      await expect(orchestratedFetch(TEST_URL, {}, CTX)).rejects.toThrow();

      expect(recordProxyOutcomeMock).toHaveBeenCalledWith(MOCK_PROXY.id, "auth_failed");
    });

    it("calls dispatchNotifications before throwing", async () => {
      undiciFetchMock.mockRejectedValueOnce(new Error("407 Proxy Authentication Required"));

      await expect(orchestratedFetch(TEST_URL, {}, CTX)).rejects.toThrow();

      expect(dispatchNotificationsMock).toHaveBeenCalledWith(
        expect.objectContaining({
          tenantId: TEST_TENANT,
          title:    expect.stringContaining("Proxy Auth Failed"),
        }),
      );
    });

    it("throws instead of falling back to direct traffic", async () => {
      undiciFetchMock.mockRejectedValueOnce(new Error("407 Proxy Authentication Required"));

      await expect(orchestratedFetch(TEST_URL, {}, CTX)).rejects.toThrow(
        /require_proxies=true/,
      );
    });
  });
});
