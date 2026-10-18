import { TelemetryService, dbWriteDuration, DbWriteOperation } from "./telemetry.service";
import { Telemetry } from "./telemetry.decorator";
import { register } from "../config/metrics";
import {
  businessOperationDuration,
  businessOperationTotal,
  businessFailureTotal,
  conversionFunnelTotal,
} from "../monitoring/monitoring.metrics";

describe("TelemetryService & @Telemetry", () => {
  let service: TelemetryService;

  beforeEach(() => {
    service = new TelemetryService();
  });

  describe("maskSensitiveData", () => {
    it("should mask sensitive keys in nested objects", () => {
      const input = {
        userId: "usr_123",
        password: "SuperSecretPassword123!",
        secret: "my-vault-secret",
        seed: "twelve words mnemonic seed phrase here",
        privateKey: "0x1234567890abcdef",
        token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-IDcSemACt8x4iTMCda8Yhe3iZaWbvV5XKSTbuAn0M",
        profile: {
          email: "user@example.com",
          apiKey: "sk_live_123456789",
          nested: {
            authorization: "Bearer secret-token",
          },
        },
      };

      const sanitized: any = service.maskSensitiveData(input);

      expect(sanitized.userId).toBe("usr_123");
      expect(sanitized.password).toBe("[REDACTED]");
      expect(sanitized.secret).toBe("[REDACTED]");
      expect(sanitized.seed).toBe("[REDACTED]");
      expect(sanitized.privateKey).toBe("[REDACTED]");
      expect(sanitized.token).toBe("[REDACTED]");
      expect(sanitized.profile.email).toBe("user@example.com");
      expect(sanitized.profile.apiKey).toBe("[REDACTED]");
      expect(sanitized.profile.nested.authorization).toBe("[REDACTED]");
    });

    it("should mask JWTs and Stellar private keys inside string values", () => {
      const jwt =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgN_b_error_token_payload";
      const stellarSecret = "SCZANGBA5YHTNYVVV4C3U252E2B6P6F5T3UM6OH4XA7QXIF4DOWSBOIS";

      const text = `User authenticated with ${jwt} and key ${stellarSecret}`;
      const sanitized = service.maskSensitiveData(text);

      expect(sanitized).toContain("[REDACTED_JWT]");
      expect(sanitized).toContain("[REDACTED_STELLAR_SECRET]");
      expect(sanitized).not.toContain(stellarSecret);
    });

    it("should leave null, undefined, and non-sensitive values unchanged", () => {
      expect(service.maskSensitiveData(null)).toBeNull();
      expect(service.maskSensitiveData(undefined)).toBeUndefined();
      expect(service.maskSensitiveData(42)).toBe(42);
      expect(service.maskSensitiveData("safe-text")).toBe("safe-text");
    });
  });

  describe("recordOperation", () => {
    it("should record a successful operation with standardized fields", () => {
      const durationSpy = jest.spyOn(businessOperationDuration, "labels");
      const totalSpy = jest.spyOn(businessOperationTotal, "labels");

      const event = service.recordOperation({
        operation: "wallet.authenticate",
        actorType: "user",
        result: "success",
        latencyMs: 45.2,
        correlationId: "corr-1234",
        funnel: "auth_onboarding",
        step: "wallet_verify",
        metadata: { client: "web" },
      });

      expect(event.operation).toBe("wallet.authenticate");
      expect(event.actor_type).toBe("user");
      expect(event.result).toBe("success");
      expect(event.latency_ms).toBe(45.2);
      expect(event.correlation_id).toBe("corr-1234");
      expect(event.timestamp).toBeDefined();
      expect(event.metadata).toEqual({ client: "web" });

      expect(durationSpy).toHaveBeenCalledWith(
        "wallet.authenticate",
        "user",
        "success",
      );
      expect(totalSpy).toHaveBeenCalledWith(
        "wallet.authenticate",
        "user",
        "success",
      );
    });

    it("should record a failed operation and increment failure total by error code", () => {
      const failureSpy = jest.spyOn(businessFailureTotal, "labels");
      const funnelSpy = jest.spyOn(conversionFunnelTotal, "labels");

      const event = service.recordOperation({
        operation: "payment.process",
        actorType: "user",
        result: "failure",
        latencyMs: 120.5,
        errorCode: "INSUFFICIENT_FUNDS",
        funnel: "payment_settlement",
        step: "payment_submit",
      });

      expect(event.result).toBe("failure");
      expect(event.error_code).toBe("INSUFFICIENT_FUNDS");

      expect(failureSpy).toHaveBeenCalledWith(
        "payment.process",
        "user",
        "INSUFFICIENT_FUNDS",
      );
      expect(funnelSpy).toHaveBeenCalledWith(
        "payment_settlement",
        "payment_submit",
        "failed",
      );
    });
  });

  describe("recordFunnelStep", () => {
    it("should update conversion funnel metric with step status", () => {
      const funnelSpy = jest.spyOn(conversionFunnelTotal, "labels");

      service.recordFunnelStep(
        "payment_settlement",
        "reconciliation_match",
        "completed",
        { invoiceId: "inv_123" },
      );

      expect(funnelSpy).toHaveBeenCalledWith(
        "payment_settlement",
        "reconciliation_match",
        "completed",
      );
    });
  });

  describe("startTimer", () => {
    it("should measure operation latency and return telemetry event", async () => {
      const endTimer = service.startTimer("portfolio.optimize", {
        actorType: "user",
        funnel: "portfolio_management",
        step: "portfolio_optimize",
      });

      await new Promise((r) => setTimeout(r, 10));

      const event = endTimer("success", undefined, { strategy: "max_sharpe" });

      expect(event.operation).toBe("portfolio.optimize");
      expect(event.result).toBe("success");
      expect(event.latency_ms).toBeGreaterThanOrEqual(5);
    });
  });

  describe("@Telemetry decorator", () => {
    class TestService {
      @Telemetry({
        operation: "test.operation",
        actorType: "test_actor",
        funnel: "test_funnel",
        step: "step_1",
      })
      async successfulMethod(req?: any) {
        return { ok: true };
      }

      @Telemetry({
        operation: "test.failing_operation",
        actorType: "test_actor",
      })
      async failingMethod(req?: any) {
        const err: any = new Error("Simulated failure");
        err.errorCode = "CUSTOM_FAILURE_CODE";
        throw err;
      }
    }

    it("should instrument successful method and capture correlation ID from request", async () => {
      const instance = new TestService();
      const mockReq = {
        headers: { "x-correlation-id": "req-corr-999" },
        user: { role: "operator" },
      };

      const result = await instance.successfulMethod(mockReq);
      expect(result).toEqual({ ok: true });
    });

    it("should capture error code and record failure on exception", async () => {
      const instance = new TestService();
      await expect(instance.failingMethod()).rejects.toThrow("Simulated failure");
    });
  });

  describe("db_write_duration_seconds metrics", () => {
    beforeEach(() => {
      dbWriteDuration.reset();
    });

    it("should have expected histogram buckets configured", () => {
      const expectedBuckets = [0.01, 0.05, 0.1, 0.5, 1.0, 5.0];
      const metric = (register as any).getSingleMetric("db_write_duration_seconds");
      expect(metric).toBeDefined();
      expect((metric as any).bucketValues).toBeDefined();
      // prom-client bucketValues maps to configured buckets
      for (const bucket of expectedBuckets) {
        expect((metric as any).bucketValues[bucket]).toBeDefined();
      }
    });

    it("should record execution duration for entity save, insert, update, and delete calls", () => {
      const observeSpy = jest.spyOn(dbWriteDuration, "labels");

      const operations: DbWriteOperation[] = ["save", "insert", "update", "delete"];
      for (const op of operations) {
        service.recordDatabaseWrite({
          operation: op,
          entity: "UserEntity",
          durationSeconds: 0.045,
          status: "success",
        });

        expect(observeSpy).toHaveBeenCalledWith(op, "UserEntity", "success");
      }
    });

    it("should measure database write duration using startDbWriteTimer helper", async () => {
      const endTimer = service.startDbWriteTimer("insert", { entity: "Portfolio" });
      await new Promise((r) => setTimeout(r, 15));
      endTimer("success");

      const metricsOutput = await register.metrics();
      expect(metricsOutput).toContain('db_write_duration_seconds_bucket{le="0.05",operation="insert",entity="Portfolio",status="success"}');
      expect(metricsOutput).toContain('db_write_duration_seconds_count{operation="insert",entity="Portfolio",status="success"} 1');
    });

    it("should measure database write callback via trackDatabaseWrite", async () => {
      const result = await service.trackDatabaseWrite("save", "PaymentOperation", async () => {
        await new Promise((r) => setTimeout(r, 10));
        return { saved: true };
      });

      expect(result).toEqual({ saved: true });

      const metricsOutput = await register.metrics();
      expect(metricsOutput).toContain('operation="save"');
      expect(metricsOutput).toContain('entity="PaymentOperation"');
      expect(metricsOutput).toContain('status="success"');
    });

    it("should record failure status when trackDatabaseWrite throws", async () => {
      await expect(
        service.trackDatabaseWrite("delete", "Session", async () => {
          throw new Error("DB lock timeout");
        }),
      ).rejects.toThrow("DB lock timeout");

      const metricsOutput = await register.metrics();
      expect(metricsOutput).toContain('operation="delete"');
      expect(metricsOutput).toContain('entity="Session"');
      expect(metricsOutput).toContain('status="failure"');
    });

    it("should expose db_write_duration_seconds on /metrics registry with valid syntax", async () => {
      service.recordDatabaseWrite({
        operation: "update",
        entity: "Account",
        durationSeconds: 0.12,
        status: "success",
      });

      const metricsText = await register.metrics();
      expect(metricsText).toContain("# HELP db_write_duration_seconds Duration of database write operations in seconds");
      expect(metricsText).toContain("# TYPE db_write_duration_seconds histogram");
      expect(metricsText).toMatch(/db_write_duration_seconds_bucket\{.*le="0\.01".*\} \d+/);
      expect(metricsText).toMatch(/db_write_duration_seconds_bucket\{.*le="0\.05".*\} \d+/);
      expect(metricsText).toMatch(/db_write_duration_seconds_bucket\{.*le="0\.1".*\} \d+/);
      expect(metricsText).toMatch(/db_write_duration_seconds_bucket\{.*le="0\.5".*\} \d+/);
      expect(metricsText).toMatch(/db_write_duration_seconds_bucket\{.*le="1".*\} \d+/);
      expect(metricsText).toMatch(/db_write_duration_seconds_bucket\{.*le="5".*\} \d+/);
      expect(metricsText).toMatch(/db_write_duration_seconds_bucket\{.*le="\+Inf".*\} \d+/);
      expect(metricsText).toContain('db_write_duration_seconds_sum{operation="update",entity="Account",status="success"}');
      expect(metricsText).toContain('db_write_duration_seconds_count{operation="update",entity="Account",status="success"} 1');
    });
  });

  describe("high-cardinality protection (#214)", () => {
    const REAL_JWT =
      "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkxLUyB0ZXN0In0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c";

    const ORIGINAL_BUDGET = process.env.TELEMETRY_LABEL_BUDGET;
    const ORIGINAL_RATE = process.env.TELEMETRY_LOG_SAMPLE_RATE;

    beforeEach(() => {
      // The rejection/suppression counters are shared singletons; restore the
      // spies earlier tests left behind so call assertions start clean.
      jest.restoreAllMocks();
    });

    afterEach(() => {
      if (ORIGINAL_BUDGET === undefined) delete process.env.TELEMETRY_LABEL_BUDGET;
      else process.env.TELEMETRY_LABEL_BUDGET = ORIGINAL_BUDGET;
      if (ORIGINAL_RATE === undefined) delete process.env.TELEMETRY_LOG_SAMPLE_RATE;
      else process.env.TELEMETRY_LOG_SAMPLE_RATE = ORIGINAL_RATE;
    });

    it("normalizes identifier-shaped and token-shaped label values before they reach Prometheus", () => {
      const totalSpy = jest.spyOn(businessOperationTotal, "labels");
      const failureSpy = jest.spyOn(businessFailureTotal, "labels");

      service.recordOperation({
        operation: "wallet.550e8400-e29b-41d4-a716-446655440000",
        actorType: "user@example.com",
        result: "failure",
        errorCode: `AUTH_FAILED_${REAL_JWT}`,
        latencyMs: 10,
      });

      // Raw identifiers and tokens never become series keys; the observation
      // is still counted under the placeholder so totals stay exact.
      expect(totalSpy).toHaveBeenCalledWith("wallet.:uuid", ":email", "failure");
      expect(failureSpy).toHaveBeenCalledWith(
        "wallet.:uuid",
        ":email",
        "__sensitive__",
      );
    });

    it("collapses a flood of distinct operation names into the overflow bucket once the budget is spent", () => {
      process.env.TELEMETRY_LABEL_BUDGET = "2";
      const sampled = new TelemetryService();
      const totalSpy = jest.spyOn(businessOperationTotal, "labels");

      for (const name of ["op_1", "op_2", "op_3", "op_4"]) {
        sampled.recordOperation({
          operation: name,
          actorType: "user",
          result: "success",
          latencyMs: 10,
        });
      }

      // The first two distinct values keep their series; every new value
      // after the budget is aggregated instead of minting a series.
      expect(totalSpy).toHaveBeenNthCalledWith(1, "op_1", "user", "success");
      expect(totalSpy).toHaveBeenNthCalledWith(2, "op_2", "user", "success");
      expect(totalSpy).toHaveBeenNthCalledWith(3, "__over_budget__", "user", "success");
      expect(totalSpy).toHaveBeenNthCalledWith(4, "__over_budget__", "user", "success");
    });

    it("samples success logs deterministically, never samples failures, and never samples metrics", () => {
      process.env.TELEMETRY_LOG_SAMPLE_RATE = "0.5";
      const sampled = new TelemetryService();
      const logSpy = jest.spyOn((sampled as any).logger, "log");
      const warnSpy = jest.spyOn((sampled as any).logger, "warn");
      const totalSpy = jest.spyOn(businessOperationTotal, "labels");

      for (let i = 0; i < 4; i += 1) {
        sampled.recordOperation({
          operation: "wallet.sign",
          actorType: "user",
          result: "success",
          latencyMs: 10,
        });
      }
      sampled.recordOperation({
        operation: "wallet.sign",
        actorType: "user",
        result: "failure",
        errorCode: "REJECTED",
        latencyMs: 10,
      });

      // Success logs land on every 2nd eligible line (deterministic cadence).
      expect(logSpy).toHaveBeenCalledTimes(2);
      // Failures always emit.
      expect(warnSpy).toHaveBeenCalledTimes(1);
      // Metrics reflect every observation exactly — sampling is log-only.
      expect(totalSpy).toHaveBeenCalledTimes(5);
    });

    it("always emits failed funnel transitions even when sampling is aggressive", () => {
      process.env.TELEMETRY_LOG_SAMPLE_RATE = "0";
      const sampled = new TelemetryService();
      const logSpy = jest.spyOn((sampled as any).logger, "log");

      sampled.recordFunnelStep("onboarding", "kyc_review", "started");
      sampled.recordFunnelStep("onboarding", "kyc_review", "completed");
      sampled.recordFunnelStep("onboarding", "kyc_review", "failed");

      // The failed transition is a failure signal; started/completed at
      // rate 0 are suppressed (metrics still recorded — see funnel metric).
      expect(logSpy).toHaveBeenCalledTimes(1);
      expect(logSpy.mock.calls[0][0]).toContain('"status":"failed"');
    });

    it("redacts sensitive tokens from emitted log lines", () => {
      const warnSpy = jest.spyOn((service as any).logger, "warn");

      service.recordOperation({
        operation: "auth.check",
        actorType: "user",
        result: "failure",
        errorCode: REAL_JWT,
        latencyMs: 10,
      });

      const line = warnSpy.mock.calls[0][0] as string;
      expect(line).not.toContain(REAL_JWT);
      expect(line).toContain("REDACTED");
    });

    it("caps oversized metadata on the log line but not on the returned event", () => {
      const logSpy = jest.spyOn((service as any).logger, "log");
      const metadata = { payload: "x".repeat(10_000) };

      const event = service.recordOperation({
        operation: "batch.import",
        actorType: "service_actor",
        result: "success",
        latencyMs: 10,
        metadata,
      });

      // Callers keep the full object — the caps bound stdout, not the API.
      expect(event.metadata).toEqual(metadata);

      const line = logSpy.mock.calls[0][0] as string;
      expect(line.length).toBeLessThan(4096);
      expect(line).toContain('"_truncated":true');
      expect(line).not.toContain("x".repeat(1_000));
    });
  });
});
