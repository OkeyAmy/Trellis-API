import client from "prom-client";
import { register } from "../config/metrics";

/**
 * High-cardinality telemetry protection (#214).
 *
 * Prometheus labels and structured log lines are only as safe as the values
 * callers put in them. A label value sourced from anything a client can
 * influence (a route parameter, a JWT claim, an error message, a channel id)
 * mints one time series per distinct value: memory grows without bound, the
 * scrape payload balloons, and dashboards drown in series nobody created on
 * purpose. Log lines have the symmetric problem — unbounded volume and
 * payload size under abusive traffic.
 *
 * `TelemetryGuard` is the single choke point between callers and the
 * telemetry sinks, enforcing three rules:
 *
 *  1. **Unsafe labels are rejected as-is** — the raw value never reaches the
 *     metric. Each value is normalized (sensitive tokens redacted,
 *     identifiers collapsed to placeholders, charset and length bounded) and
 *     then counted against a per-`metric::label` **cardinality budget**;
 *     values beyond the budget collapse into `__over_budget__` instead of
 *     minting a new series. Observations are never dropped — they are
 *     aggregated — so totals and rates stay correct and dashboards stay
 *     useful. Every collapse increments `trellis_telemetry_label_rejections_total`
 *     (`metric`, `label`, `reason`) so operators can see *which* caller is
 *     leaking cardinality and fix it at the source.
 *  2. **Redaction applies to log lines** — the serialized line runs through
 *     the existing sensitive-data mask (JWTs, Stellar secrets, sensitive
 *     keys), and every free-text field is length-capped so one hostile field
 *     cannot emit a multi-megabyte line.
 *  3. **Sampling keeps volume bounded** — failure events are never sampled
 *     out (they are the signal), success/funnel events are sampled
 *     deterministically at a configurable rate, and suppressed lines are
 *     counted in `trellis_telemetry_log_events_suppressed_total` so the
 *     reduction is observable. Prometheus series are *never* sampled:
 *     metrics always reflect every observation exactly.
 *
 * Determinism matters: sampling uses an accumulator over event order rather
 * than randomness, so a test (or an operator replaying a trace) gets the same
 * answers for the same sequence of events.
 */

/** Why a raw label value was not recorded verbatim. Closed set — bounded as a label. */
export type LabelRejectionReason =
  | "type_mismatch"
  | "sensitive"
  | "identifier"
  | "charset"
  | "too_long"
  | "cardinality";

/** Log kinds sampling applies to. Closed set — bounded as a label. */
export type LogKind = "operation" | "funnel";

/** Maximum recorded metric-label length after normalization. */
export const LABEL_VALUE_MAX_LENGTH = 64;

/** Distinct values allowed per `metric :: label` before collapsing. */
export const DEFAULT_LABEL_BUDGET = 128;

/** Default log sampling rate: 1 = emit every eligible line (existing behaviour). */
export const DEFAULT_LOG_SAMPLE_RATE = 1;

/** Per-field caps for serialized log lines. */
export const LOG_OPERATION_MAX_LENGTH = 512;
export const LOG_SHORT_FIELD_MAX_LENGTH = 128;
export const LOG_METADATA_MAX_BYTES = 2048;

// Patterns for values that are safe as data but unsafe as series names.
const JWT_PATTERN = /eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}/;
const STELLAR_SECRET_PATTERN = /\bS[A-Z2-7]{55}\b/;
const UUID_PATTERN = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi;
const ETH_ADDRESS_PATTERN = /0x[0-9a-f]{40}/gi;
const TX_HASH_PATTERN = /0x[0-9a-f]{64}/gi;
const EMAIL_PATTERN = /[^\s@]+@[^\s@]+\.[^\s@]+/g;
const WHOLE_NUMBER_PATTERN = /^\d+$/;
const UNSAFE_CHARSET_PATTERN = /[^A-Za-z0-9_:.-]/g;

function getOrCreateCounter(config: client.CounterConfiguration<string>): client.Counter {
  const existing = register.getSingleMetric(config.name);
  if (existing) return existing as client.Counter;
  return new client.Counter({ ...config, registers: [register] });
}

/**
 * Rejected label values, by metric and label. `reason` is the first rule that
 * fired, so the series tells an operator where to fix the caller.
 */
export const telemetryLabelRejections = getOrCreateCounter({
  name: "trellis_telemetry_label_rejections_total",
  help: "Telemetry label values that were rejected (normalized or collapsed) instead of recorded verbatim",
  labelNames: ["metric", "label", "reason"],
});

/** Log lines a sampled-out event would have emitted, by kind. */
export const telemetryLogSuppressed = getOrCreateCounter({
  name: "trellis_telemetry_log_events_suppressed_total",
  help: "Telemetry log lines suppressed by sampling rules (metrics are never sampled)",
  labelNames: ["kind"],
});

function envNumber(
  name: string,
  fallback: number,
  min: number,
  max: number,
): number {
  const raw = process.env[name];
  if (raw === undefined || raw.trim() === "") return fallback;
  const parsed = Number(raw);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(max, Math.max(min, parsed));
}

function clampNumber(
  value: number,
  min: number,
  max: number,
  fallback: number,
): number {
  if (!Number.isFinite(value)) return fallback;
  return Math.min(max, Math.max(min, value));
}

function clampInt(
  value: number,
  min: number,
  max: number,
  fallback: number,
): number {
  if (!Number.isFinite(value)) return fallback;
  return Math.floor(Math.min(max, Math.max(min, value)));
}

export interface TelemetryGuardOptions {
  /** Distinct values per `metric :: label` before collapsing. Env: `TELEMETRY_LABEL_BUDGET`. */
  labelBudget?: number;
  /** Fraction of eligible (non-failure) log lines to emit, 0..1. Env: `TELEMETRY_LOG_SAMPLE_RATE`. */
  logSampleRate?: number;
  /** Serialized log-line budget for metadata JSON, in bytes. */
  logMetadataMaxBytes?: number;
}

export class TelemetryGuard {
  /** Distinct-value budget per `metric\u0000label`; read-only for inspection. */
  readonly labelBudget: number;
  /** Sampling rate for non-failure log lines; 1 emits all (default). */
  readonly logSampleRate: number;
  /** Metadata JSON size above which the log copy is replaced by a placeholder. */
  readonly logMetadataMaxBytes: number;

  private readonly budgets = new Map<string, Set<string>>();
  private readonly sampleAccumulator = new Map<LogKind, number>();

  constructor(options: TelemetryGuardOptions = {}) {
    // Precedence: explicit option > environment > default; invalid values
    // fall back rather than disable protection.
    this.labelBudget = clampInt(
      options.labelBudget ??
        envNumber("TELEMETRY_LABEL_BUDGET", DEFAULT_LABEL_BUDGET, 1, 100_000),
      1,
      100_000,
      DEFAULT_LABEL_BUDGET,
    );
    this.logSampleRate = clampNumber(
      options.logSampleRate ??
        envNumber(
          "TELEMETRY_LOG_SAMPLE_RATE",
          DEFAULT_LOG_SAMPLE_RATE,
          0,
          1,
        ),
      0,
      1,
      DEFAULT_LOG_SAMPLE_RATE,
    );
    this.logMetadataMaxBytes = clampInt(
      options.logMetadataMaxBytes ?? LOG_METADATA_MAX_BYTES,
      256,
      1024 * 1024,
      LOG_METADATA_MAX_BYTES,
    );
  }

  /**
   * Normalize one label value for `metric` and account it against that
   * metric/label's cardinality budget. The raw value is never recorded when
   * any rule fires; the returned placeholder keeps the observation counted.
   */
  boundLabel(metric: string, label: string, value: unknown): string {
    let reason: LabelRejectionReason | null = null;
    let normalized: string;

    if (typeof value === "string") {
      normalized = value;
    } else if (typeof value === "number" && Number.isFinite(value)) {
      normalized = String(value);
    } else {
      // undefined, null, objects, NaN, Infinity — nothing usable as a series key.
      normalized = "__invalid__";
      reason = "type_mismatch";
    }

    if (reason === null) {
      const trimmed = normalized.trim();
      if (trimmed.length === 0) {
        normalized = "__invalid__";
        reason = "type_mismatch";
      } else {
        normalized = trimmed;
      }
    }

    // Secrets must never become series keys, even as fragments.
    if (reason === null && (JWT_PATTERN.test(normalized) || STELLAR_SECRET_PATTERN.test(normalized))) {
      normalized = "__sensitive__";
      reason = "sensitive";
    }

    // Identifiers that are legitimate data but unbounded as keys: collapse
    // the identifying part while keeping surrounding context.
    if (reason === null) {
      const collapsed = normalized
        .replace(UUID_PATTERN, ":uuid")
        .replace(TX_HASH_PATTERN, ":txhash")
        .replace(ETH_ADDRESS_PATTERN, ":address")
        .replace(EMAIL_PATTERN, ":email");
      if (collapsed !== normalized) {
        normalized = collapsed;
        reason = "identifier";
      }
    }
    if (reason === null && WHOLE_NUMBER_PATTERN.test(normalized)) {
      normalized = ":id";
      reason = "identifier";
    }

    if (reason === null) {
      const cleaned = normalized.replace(UNSAFE_CHARSET_PATTERN, "_");
      if (cleaned !== normalized) {
        normalized = cleaned;
        reason = "charset";
      }
    }

    if (reason === null && normalized.length > LABEL_VALUE_MAX_LENGTH) {
      normalized = normalized.slice(0, LABEL_VALUE_MAX_LENGTH);
      reason = "too_long";
    }

    // Budget: values already seen stay stable (dashboards keep their series);
    // only *new* values beyond the budget collapse. The placeholder itself is
    // not counted against the budget.
    const key = `${metric}\u0000${label}`;
    let seen = this.budgets.get(key);
    if (!seen) {
      seen = new Set<string>();
      this.budgets.set(key, seen);
    }
    if (!seen.has(normalized)) {
      if (seen.size >= this.labelBudget) {
        normalized = "__over_budget__";
        reason = "cardinality";
      } else {
        seen.add(normalized);
      }
    }

    if (reason !== null) {
      // Counters are bounded: metric/label come from our own call sites and
      // reason is a closed set.
      telemetryLabelRejections.inc({ metric, label, reason });
    }
    return normalized;
  }

  /** Normalize a tuple of labels for one metric observation. */
  boundLabels(
    metric: string,
    labels: readonly string[],
    values: readonly unknown[],
  ): string[] {
    return labels.map((label, index) =>
      this.boundLabel(metric, label, values[index]),
    );
  }

  /**
   * Sampling decision for one log line. Failures are always emitted; eligible
   * lines follow the configured rate deterministically. Returns `false` only
   * for a suppressed line and counts it, so the reduction is observable.
   */
  shouldEmitLog(kind: LogKind, isFailure: boolean): boolean {
    if (isFailure) return true;
    if (this.logSampleRate >= 1) return true;

    const accumulator = (this.sampleAccumulator.get(kind) ?? 0) + this.logSampleRate;
    if (accumulator >= 1) {
      this.sampleAccumulator.set(kind, accumulator - 1);
      return true;
    }
    this.sampleAccumulator.set(kind, accumulator);
    telemetryLogSuppressed.inc({ kind });
    return false;
  }

  /** Test seam: clear budget state, sampling accumulators and counters. */
  reset(): void {
    this.budgets.clear();
    this.sampleAccumulator.clear();
    telemetryLabelRejections.reset();
    telemetryLogSuppressed.reset();
  }
}
