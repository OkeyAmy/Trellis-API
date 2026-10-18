# High-cardinality telemetry protection (#214)

Guard rails between callers and the telemetry sinks of
`TelemetryService`: unsafe metric-label values are rejected as-is and
aggregated, sensitive values are redacted from what gets written, and
non-failure log lines are sampled so abusive input volume cannot flood
stdout or the dashboards. Metrics series themselves are **never** sampled —
every observation still counts exactly once.

Companion to [OBSERVABILITY_TELEMETRY.md](./OBSERVABILITY_TELEMETRY.md),
which documents the event schema and metric catalogue. Implementation:
`src/observability/telemetry-guard.ts` (the guard) wired into
`src/observability/telemetry.service.ts`.

---

## 1. The problem it solves

Prometheus labels and structured logs are only as safe as the values callers
put in them. `recordOperation` labels come from sources a client can
influence over time — the `@Telemetry` decorator reads `actor_type` from
`req.user.role || req.user.type` (token claims), `error_code` comes from
`err.code || err.name`, and operations/steps are caller-chosen strings.
One series per distinct value means: a token issuer that lets users pick
their `type`, an error path that embeds a UUID or an email, or a caller
minting `operation` names from route params → unbounded in-memory series
growth, ballooning scrape payloads, and dashboards with a thousand lines
nobody created on purpose. Logs have the symmetric problem: every event
emits one JSON line with unbounded free-text fields and no volume control.

## 2. The three layers

### Layer 1 — label values are rejected as-is (never dropped)

Every label value passes through `TelemetryGuard.boundLabel(metric, label,
value)` before it reaches a metric. If any rule fires, the raw value is
**not** recorded; the observation is re-keyed under a safe placeholder so
totals and rates stay exact. The pipeline, in order (first rule that fires
determines the counted `reason`):

| # | Rule | Example input | Recorded as | Reason |
|---|------|---------------|-------------|--------|
| 1 | Non-string / non-finite / empty | `undefined`, `{}`, `NaN`, `"  "` | `__invalid__` | `type_mismatch` |
| 2 | Token or secret anywhere in the value | `AUTH_FAILED_eyJhbGci…` | `__sensitive__` | `sensitive` |
| 3 | Identifiers collapsed (UUID, Stellar secret-style base32, `0x…`40/64 hex, email) | `user-550e8400-…-0000-verify` | `user-:uuid-verify` | `identifier` |
| 4 | Whole-value pure numbers (ids) | `1234567890`, `404` | `:id` | `identifier` |
| 5 | Unsafe charset (`[^A-Za-z0-9_:.-]` → `_`) | `evil value/with?chars` | `evil_value_with_chars` | `charset` |
| 6 | Length cap 64 | 200-char string | first 64 chars | `too_long` |
| 7 | Cardinality budget (below) | new value past budget | `__over_budget__` | `cardinality` |

Surrounding whitespace is trimmed silently (not a rejection). Embedded
digits are deliberately left alone so bounded enums keep their meaning —
`HTTP_404` stays `HTTP_404`; only bare integers collapse to `:id`.

Every rejection increments `trellis_telemetry_label_rejections_total`
(labels: `metric`, `label`, `reason` — all closed sets, so the counter is
itself bounded). That counter is the operator's pointer to the caller that
needs fixing.

### Layer 2 — cardinality budget

Per `metric :: label` pair the guard remembers distinct values up to
`TELEMETRY_LABEL_BUDGET` (default 128). Values already seen keep their
series forever (dashboards stay continuous); only *new* values beyond the
budget collapse into `__over_budget__`. The placeholder itself does not
count against the budget, and budgets are isolated per metric and label, so
a flood of operation names cannot exhaust the entity budget.

### Layer 3 — redaction, payload caps and log sampling

- The serialized log line runs through the existing sensitive-data mask
  (JWTs, Stellar secrets, sensitive keys — see
  `TelemetryService.maskSensitiveData`), applied to the *whole event*, so a
  token that only appears inside a free-text field never reaches stdout.
- Free-text fields on the log copy are length-capped (`operation` 512; other
  text fields 128). Metadata whose JSON exceeds `2 KB` is replaced on the
  log copy by `{"_truncated": true, "_original_bytes": N}`. The event
  **returned to the caller keeps its original values** — the caps bound
  stdout, not the API surface.
- Non-failure log lines are sampled at `TELEMETRY_LOG_SAMPLE_RATE`
  (default `1` = emit every line, byte-compatible with previous behaviour).
  Sampling is a deterministic accumulator over event order — no randomness,
  so a replay or a test sees the same decisions for the same sequence.
  Failures (`result: "failure"`, funnel status `failed`) are **never**
  sampled out. Suppressed lines increment
  `trellis_telemetry_log_events_suppressed_total{kind}` so the reduction is
  observable.
- **Metrics are never sampled.** Sampling only ever suppresses log lines.

## 3. Configuration

| Env var | Default | Meaning |
|---|---|---|
| `TELEMETRY_LABEL_BUDGET` | `128` | Distinct values per `metric :: label` before collapsing to `__over_budget__`. Clamped to `[1, 100000]`; invalid → default. |
| `TELEMETRY_LOG_SAMPLE_RATE` | `1` | Fraction of eligible (non-failure) log lines to emit, `0..1`. Clamped; invalid → default. `0.1` ≈ one line per ten events; failures always emit. |

Both are read at process start (`TelemetryService` construction). Explicit
constructor options (`new TelemetryGuard({ labelBudget, logSampleRate })`)
take precedence over the environment, which takes precedence over defaults.

## 4. Operational edge cases

- **Budget fill mid-run.** A series that existed before the budget filled
  keeps its identity; a brand-new value arriving after fill lands in
  `__over_budget__`. If a legitimately new operation shows up as
  `__over_budget__`, raise the budget or — better — fix the caller and
  restart the process (budget state is in-memory).
- **Gauges must not route through the guard (yet).** `boundLabel` is
  stateful per budget; a gauge that `inc()`s under value X and `dec()`s
  under value Y can drift if X and Y normalize differently or the budget
  fills in between. `TelemetryService` only emits counters and histograms,
  so this cannot happen today. Adopters wiring the guard into gauge call
  sites (e.g. per-user websocket gauges in
  `dashboard-metrics.service.ts`) must either keep the label on a closed set
  or normalize without the budget.
- **Deterministic sampling cadence.** At rate `0.5` a burst of four
  successes logs lines 2 and 4. Quiet periods do not "save up" beyond one
  line per `1/rate` events. Failure lines do not consume success slots.
- **Non-string typed-contract bypasses.** `recordOperation` is typed, but
  JavaScript callers can pass anything. Metric-side, rule 1 handles it. Log
  side, non-string free-text fields are stringified then capped.
- **Correlation IDs** are log-only (never a metric label); a hostile
  10 KB `x-correlation-id` header is capped at 128 chars on the log line and
  masked like any other string.
- **Per-metric budget isolation** means fixing one noisy caller's label
  (e.g. `actor_type`) does not disturb another label on the same metric.

## 5. Failure modes and degradations

- **Telemetry never breaks the business call.** Metric emission is inside
  the existing try/catch; log serialization is inside a second try/catch
  that degrades to a short warning line. An unserializable (circular)
  metadata object no longer throws out of `recordOperation` — it is replaced
  on the log line by `{"_unserializable": true}`.
- **Guard counters are bounded by construction** (closed label sets), so the
  protection itself cannot become the cardinality incident.
- **Misconfigured rate/budget fail safe**: garbage env values fall back to
  the defaults; out-of-range values clamp. An accidentally low rate never
  suppresses failure lines.
- **What this does not protect**: log volume from *other* emit paths
  (e.g. the per-request timing console line in
  `request-timing.middleware.ts`) is unchanged; see §7.

## 6. Rollback and recovery

No schema, migration or API change — the feature is code + env only.

- **Neutralize sampling**: set `TELEMETRY_LOG_SAMPLE_RATE=1` (or unset) and
  restart; behaviour returns to one log line per event.
- **Neutralize budget collapsing**: set `TELEMETRY_LABEL_BUDGET` very high
  and restart. Pattern normalization (UUID/email/token rules) always runs —
  that is the fix, not the accident; a full revert is
  `git revert` of the #214 commit(s).
- **Recovery from a budget fill**: budget state is in-memory only. Fix the
  cardinality-leaking caller, restart the process, and the fresh budget
  admits the corrected values. The rejection counter resets with the process.
- **Diagnosing a leak**: alert on
  `rate(trellis_telemetry_label_rejections_total[5m])` grouped by
  `metric`/`label`/`reason`. `cardinality` → a caller is minting distinct
  values (find it via the metric name); `sensitive` → someone is passing
  tokens into labels (a real bug worth an incident); `identifier`/`charset`
  are hygiene warnings that the placeholder already neutralized.

## 7. Known limitations / follow-ups

- `request-timing.middleware.ts` logs one console line per request with the
  raw path and no sampling; it normalizes paths for metrics only. Adopting
  the guard there (normalized path + rate) is a natural follow-up.
- `dashboard-metrics.service.ts` uses per-`userId` gauge labels — a genuine
  per-user series explosion — but gauges need the §4 treatment first.
- `TelemetryGuard` is exported and reusable; only `TelemetryService` is
  wired in this slice (issue guidance: small, well-tested vertical slice).

## 8. Compatibility

Public APIs, event schemas and metric names are unchanged. Existing event
values pass through verbatim (tests assert the full before/after for
legitimate operations); metric label values for legitimate operations are
unchanged, so existing dashboards and alerts keep matching. Default
configuration is behaviour-compatible: budget 128 and rate 1 mean no
operation, actor, or log line a well-behaved caller produces is affected.
