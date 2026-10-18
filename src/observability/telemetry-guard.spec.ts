import {
  DEFAULT_LABEL_BUDGET,
  DEFAULT_LOG_SAMPLE_RATE,
  LABEL_VALUE_MAX_LENGTH,
  TelemetryGuard,
  telemetryLabelRejections,
  telemetryLogSuppressed,
} from "./telemetry-guard";

/*
 * Self-tests for the high-cardinality telemetry guard (#214). The budget and
 * sampling assertions are load-bearing: if either silently degrades, abusive
 * input starts minting Prometheus series or flooding stdout again with
 * nothing in the suite to notice.
 */
describe("TelemetryGuard", () => {
  // The rejection/suppression counters are module singletons shared across
  // tests in this file; restore spies after each test so call assertions
  // never see another test's traffic.
  afterEach(() => {
    jest.restoreAllMocks();
  });

  const JWT =
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgN_b_error_token_payload";
  const STELLAR_SECRET = "SCZANGBA5YHTNYVVV4C3U252E2B6P6F5T3UM6OH4XA7QXIF4DOWSBOIS";

  describe("boundLabel — safe values pass through unchanged", () => {
    it("keeps legitimate operation, actor and enum values verbatim", () => {
      const guard = new TelemetryGuard();
      expect(guard.boundLabel("m", "operation", "wallet.authenticate")).toBe(
        "wallet.authenticate",
      );
      expect(guard.boundLabel("m", "actor_type", "user")).toBe("user");
      expect(guard.boundLabel("m", "result", "success")).toBe("success");
      expect(guard.boundLabel("m", "error_code", "INSUFFICIENT_FUNDS")).toBe(
        "INSUFFICIENT_FUNDS",
      );
      // HTTP_404 must not be mangled by the digit rule (only whole-number
      // values collapse to :id).
      expect(guard.boundLabel("m", "error_code", "HTTP_404")).toBe("HTTP_404");
    });

    it("collapses bare numbers to :id (the most common unbounded-label leak)", () => {
      const guard = new TelemetryGuard();
      // A raw integer label is almost always an id; bounded enums should be
      // passed as explicit strings ("HTTP_404") which stay verbatim.
      expect(guard.boundLabel("m", "status_code", 404)).toBe(":id");
      expect(guard.boundLabel("m", "latency_bucket", 0)).toBe(":id");
    });

    it("trims surrounding whitespace without counting a rejection", () => {
      const guard = new TelemetryGuard();
      const rejections = jest.spyOn(telemetryLabelRejections, "inc");
      expect(guard.boundLabel("m", "actor_type", "  user  ")).toBe("user");
      expect(rejections).not.toHaveBeenCalled();
    });
  });

  describe("boundLabel — unsafe values are rejected as-is", () => {
    it("rejects non-string, non-finite and empty values as __invalid__", () => {
      const guard = new TelemetryGuard();
      const rejections = jest.spyOn(telemetryLabelRejections, "inc");

      expect(guard.boundLabel("m", "actor_type", undefined)).toBe("__invalid__");
      expect(guard.boundLabel("m", "actor_type", null)).toBe("__invalid__");
      expect(guard.boundLabel("m", "actor_type", { role: "admin" })).toBe(
        "__invalid__",
      );
      expect(guard.boundLabel("m", "actor_type", Number.NaN)).toBe("__invalid__");
      expect(guard.boundLabel("m", "actor_type", "   ")).toBe("__invalid__");

      for (let call = 0; call < 5; call += 1) {
        expect(rejections).toHaveBeenLastCalledWith({
          metric: "m",
          label: "actor_type",
          reason: "type_mismatch",
        });
      }
    });

    it("redacts tokens and secrets instead of recording them as series keys", () => {
      const guard = new TelemetryGuard();
      expect(guard.boundLabel("m", "error_code", `HTTP_401_${JWT}`)).toBe(
        "__sensitive__",
      );
      expect(guard.boundLabel("m", "error_code", STELLAR_SECRET)).toBe(
        "__sensitive__",
      );
    });

    it("collapses identifiers to placeholders while keeping context", () => {
      const guard = new TelemetryGuard();
      const uuid = "550e8400-e29b-41d4-a716-446655440000";
      const address = `0x${"a".repeat(40)}`;
      const txHash = `0x${"b".repeat(64)}`;

      expect(guard.boundLabel("m", "operation", uuid)).toBe(":uuid");
      expect(guard.boundLabel("m", "operation", `user-${uuid}-verify`)).toBe(
        "user-:uuid-verify",
      );
      expect(guard.boundLabel("m", "actor_type", "ops@trellis.example")).toBe(
        ":email",
      );
      expect(guard.boundLabel("m", "operation", address)).toBe(":address");
      expect(guard.boundLabel("m", "operation", `send-${address}`)).toBe(
        "send-:address",
      );
      // The 64-hex rule must win over the 40-hex one for full tx hashes.
      expect(guard.boundLabel("m", "operation", txHash)).toBe(":txhash");
      expect(guard.boundLabel("m", "operation", "1234567890")).toBe(":id");
      // Embedded digits are left alone (HTTP_404 must keep its meaning);
      // open-ended identifiers like usr_N are the budget's job, not regexes.
      expect(guard.boundLabel("m", "error_code", "HTTP_404")).toBe("HTTP_404");
      expect(guard.boundLabel("m", "actor_type", "usr_42")).toBe("usr_42");
    });

    it("replaces unsafe characters and enforces the length cap", () => {
      const guard = new TelemetryGuard();
      expect(guard.boundLabel("m", "operation", "evil value/with?chars")).toBe(
        "evil_value_with_chars",
      );
      expect(guard.boundLabel("m", "operation", "x".repeat(200))).toHaveLength(
        LABEL_VALUE_MAX_LENGTH,
      );
    });
  });

  describe("cardinality budget", () => {
    it("collapses values beyond the budget and keeps seen values stable", () => {
      const guard = new TelemetryGuard({ labelBudget: 3 });
      const rejections = jest.spyOn(telemetryLabelRejections, "inc");

      expect(guard.boundLabel("m", "operation", "op-1")).toBe("op-1");
      expect(guard.boundLabel("m", "operation", "op-2")).toBe("op-2");
      expect(guard.boundLabel("m", "operation", "op-3")).toBe("op-3");
      expect(rejections).not.toHaveBeenCalled();

      // New values past the budget collapse instead of minting a series...
      expect(guard.boundLabel("m", "operation", "op-4")).toBe("__over_budget__");
      expect(guard.boundLabel("m", "operation", "op-5")).toBe("__over_budget__");
      expect(rejections).toHaveBeenCalledWith({
        metric: "m",
        label: "operation",
        reason: "cardinality",
      });

      // ...but values already recorded keep their series (dashboards stay
      // continuous), and the overflow placeholder is not counted as a value.
      expect(guard.boundLabel("m", "operation", "op-1")).toBe("op-1");
      expect(guard.boundLabel("m", "operation", "op-6")).toBe("__over_budget__");
    });

    it("budgets each metric :: label independently", () => {
      const guard = new TelemetryGuard({ labelBudget: 1 });
      guard.boundLabel("metric_a", "operation", "shared-op");
      expect(guard.boundLabel("metric_b", "operation", "shared-op")).toBe(
        "shared-op",
      );
      expect(guard.boundLabel("metric_a", "entity", "shared-op")).toBe(
        "shared-op",
      );
      expect(guard.boundLabel("metric_a", "operation", "other-op")).toBe(
        "__over_budget__",
      );
    });

    it("boundLabels normalizes a whole tuple against one metric", () => {
      const guard = new TelemetryGuard({ labelBudget: 2 });
      const labels = guard.boundLabels("metric", ["operation", "actor_type", "result"], [
        "wallet.authenticate",
        undefined,
        "success",
      ]);
      expect(labels).toEqual(["wallet.authenticate", "__invalid__", "success"]);
    });
  });

  describe("shouldEmitLog — sampling rules", () => {
    it("emits everything at the default rate", () => {
      const guard = new TelemetryGuard();
      const suppressed = jest.spyOn(telemetryLogSuppressed, "inc");
      for (let i = 0; i < 10; i += 1) {
        expect(guard.shouldEmitLog("operation", false)).toBe(true);
      }
      expect(suppressed).not.toHaveBeenCalled();
    });

    it("never samples out failures, even at rate 0", () => {
      const guard = new TelemetryGuard({ logSampleRate: 0 });
      expect(guard.shouldEmitLog("operation", true)).toBe(true);
      expect(guard.shouldEmitLog("funnel", true)).toBe(true);
      const suppressed = jest.spyOn(telemetryLogSuppressed, "inc");
      expect(guard.shouldEmitLog("operation", false)).toBe(false);
      expect(suppressed).toHaveBeenCalledWith({ kind: "operation" });
    });

    it("samples deterministically at fractional rates", () => {
      const half = new TelemetryGuard({ logSampleRate: 0.5 });
      expect([1, 2, 3, 4].map(() => half.shouldEmitLog("operation", false))).toEqual([
        false,
        true,
        false,
        true,
      ]);

      const quarter = new TelemetryGuard({ logSampleRate: 0.25 });
      expect([1, 2, 3, 4].map(() => quarter.shouldEmitLog("operation", false))).toEqual([
        false,
        false,
        false,
        true,
      ]);
    });

    it("keeps sampling state independent per log kind", () => {
      const guard = new TelemetryGuard({ logSampleRate: 0.5 });
      expect(guard.shouldEmitLog("operation", false)).toBe(false);
      // The funnel accumulator is untouched, so it lands on its own cadence.
      expect(guard.shouldEmitLog("funnel", false)).toBe(false);
      expect(guard.shouldEmitLog("operation", false)).toBe(true);
      expect(guard.shouldEmitLog("funnel", false)).toBe(true);
    });
  });

  describe("configuration", () => {
    const ORIGINAL_BUDGET = process.env.TELEMETRY_LABEL_BUDGET;
    const ORIGINAL_RATE = process.env.TELEMETRY_LOG_SAMPLE_RATE;

    afterEach(() => {
      if (ORIGINAL_BUDGET === undefined) delete process.env.TELEMETRY_LABEL_BUDGET;
      else process.env.TELEMETRY_LABEL_BUDGET = ORIGINAL_BUDGET;
      if (ORIGINAL_RATE === undefined) delete process.env.TELEMETRY_LOG_SAMPLE_RATE;
      else process.env.TELEMETRY_LOG_SAMPLE_RATE = ORIGINAL_RATE;
    });

    it("reads budget and rate from the environment", () => {
      process.env.TELEMETRY_LABEL_BUDGET = "7";
      process.env.TELEMETRY_LOG_SAMPLE_RATE = "0.5";
      const guard = new TelemetryGuard();
      expect(guard.labelBudget).toBe(7);
      expect(guard.logSampleRate).toBe(0.5);
    });

    it("falls back to defaults on garbage and clamps out-of-range values", () => {
      process.env.TELEMETRY_LABEL_BUDGET = "not-a-number";
      process.env.TELEMETRY_LOG_SAMPLE_RATE = "7";
      const guard = new TelemetryGuard();
      expect(guard.labelBudget).toBe(DEFAULT_LABEL_BUDGET);
      expect(guard.logSampleRate).toBe(1);

      process.env.TELEMETRY_LABEL_BUDGET = "-5";
      process.env.TELEMETRY_LOG_SAMPLE_RATE = "not-a-number";
      const clamped = new TelemetryGuard();
      expect(clamped.labelBudget).toBe(1);
      expect(clamped.logSampleRate).toBe(DEFAULT_LOG_SAMPLE_RATE);
    });

    it("prefers explicit options over the environment", () => {
      process.env.TELEMETRY_LABEL_BUDGET = "7";
      const guard = new TelemetryGuard({ labelBudget: 3 });
      expect(guard.labelBudget).toBe(3);
    });
  });

  describe("reset", () => {
    it("clears budget state, accumulators and counters", () => {
      const guard = new TelemetryGuard({ labelBudget: 1, logSampleRate: 0.5 });
      guard.boundLabel("m", "operation", "op-1");
      expect(guard.boundLabel("m", "operation", "op-2")).toBe("__over_budget__");
      guard.shouldEmitLog("operation", false);

      guard.reset();

      // Budget freed, so op-2 is a first-class value again.
      expect(guard.boundLabel("m", "operation", "op-2")).toBe("op-2");
      expect(guard.shouldEmitLog("operation", false)).toBe(false);
    });
  });
});
