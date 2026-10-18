# Multi-actor concurrency harness (#218)

A test harness for racing **critical writes**: concurrent actors, duplicate
submissions, stale versions and retry storms, asserted as invariants rather
than as scheduling accidents. Lives at `src/testing/concurrency/`
alongside the existing `chaos/` and `fault-injection/` helpers.

```ts
import {
  runConcurrently, duplicateSubmissions, retryStorm,
  expectSuccessCount, rejectionSummary,
} from "src/testing/concurrency/concurrency-harness";

const report = await runConcurrently(5, (actor) => mutateCriticalState(actor));
expectSuccessCount(report, 1);                 // exactly one winner
for (const kind of rejectionSummary(report)) { // everyone else saw 409
  expect(kind.status).toBe(409);
}
```

## Why not plain `Promise.all`

- **Races that never race.** Actors started staggered never overlap, so a
  broken claim path passes. The harness releases every actor through one
  start barrier: each operation's synchronous prefix runs before any actor
  can complete, which is the closest thing to simultaneous entry a single
  event loop offers. The barrier itself is under test — if it degrades,
  races everywhere silently stop racing.
- **Order-encoded assertions.** `expect(results[0])` encodes an accidental
  microtask ordering. Reports classify outcomes (success, or a rejection
  with status + message) so tests assert *invariants*: "exactly one
  winner", "every loser saw 409", "the handler ran once".
- **Hidden failures.** `Promise.all` aborts on the first rejection and
  hides the rest. Every actor's outcome is captured; rejections are data.

Everything is deterministic: no sleeps, no jitter, no probability — the
primitives only shape *when* flows interleave, never what they observe.

## Covered mutations

| Scenario | Target | Invariant pinned |
| --- | --- | --- |
| Concurrent actors | `ApprovalIntentService.execute` | exactly one `proposed → executing` claim; one operation run; losers get 409 |
| Duplicate submissions | `IdempotencyService.execute` | handler runs **once**; losers see 409 — never a raw unique-index 500 |
| Duplicate submissions | same intent id submitted in parallel | same single-claim invariant |
| Stale versions | intent read as `proposed`, peer completes, stale write lands | state is re-read from the store; the stale write loses with 409 |
| Stale versions | idempotency snapshot captured mid-flight | next retry replays the stored response instead of re-running |
| Retry storm (in flight) | idempotency storm over a gated handler | all attempts 409 "already in progress"; original finishes once |
| Retry storm (after completion) | terminal intent | all attempts 409; operation never re-runs |
| Withdrawal vs execution | `cancel` racing `execute` | mutually exclusive — exactly one side effect, row agrees |
| Key reuse, different payload | idempotency | winner completes once; loser gets the payload 409 |

Specs: `src/testing/concurrency/concurrency-harness.spec.ts` (self-test),
`src/common/idempotency/idempotency.concurrency.spec.ts`,
`src/infrastructure/audit/approval-intents/approval-intent.concurrency.spec.ts`.

## Edge cases this harness caught (fixed here)

1. **Unique-index losers surfaced as raw 500s.** The entity contract
   promises "the loser fails on the unique index and is mapped to a 409",
   but `IdempotencyService.execute` never caught the violation: two
   concurrent duplicates could both pass the lookup and the loser's INSERT
   raised SQLSTATE 23505 straight to the client. The claim is now a bounded
   loop — on a unique violation it re-reads the winner's record and
   replays it, rejects with 409, or (their attempt failed) claims the key.
2. **`cancel` / `expireIntent` could clobber a live execution.** Both did
   read → check → *unconditional* `save`, so a withdrawal arriving while an
   execution held the claim would rewrite `executing/completed` rows to
   `cancelled/expired` — and two racing cancellations could both "succeed"
   (double evidence). Both now claim atomically with
   `UPDATE ... WHERE status = 'proposed'` and answer 409 when the claim is
   gone, mirroring `execute`.
3. **Known limitation (documented, not yet fixed):** intent *proposal*
   dedupe (`find → insert`) is sequential-strength only. Two genuinely
   concurrent proposals of the identical commitment can both persist,
   because the table has no live-row uniqueness on `fingerprint`. The
   duplicates are still single-use, fully audited, and cancel-able; a
   hardening would be a partial unique index on
   `(fingerprint) WHERE status IN ('proposed','executing')` plus a
   unique-violation mapping. Until then: treat the dedupe as a
   footgun-reducer, not a lock.

## Failure modes operators may see

- **409 storms during a retry loop are normal.** A client hammering an
  in-flight idempotent write gets one 409 per overlapping attempt, then a
  replay of the stored response once the original completes. These are
  *correct* responses, not incidents.
- **SQLSTATE 23505 from `idempotency_records`** should never reach a
  client anymore. If it does, the claim loop's mapping regressed.
- **Stuck `in_progress` idempotency rows** occur when the process dies
  between claim and completion. The row expires at its `expiresAt` TTL
  (indexed); `purgeExpired()` sweeps them. Until expiry, retries with that
  key get 409 — see recovery below.
- **Stuck `executing` intents** occur when the process dies between the
  claim and the receipt write. The state machine keeps the row harmless
  (it can never execute twice, and no receipt claims it finished), but
  nothing auto-transitions it — recover explicitly, below.
- **Cancel/expire 409s with the current status in the message** now mean
  "you lost a race", not "your intent id is wrong" — a wrong id still
  404s.

## Rollback / recovery steps

**Operational recovery (no deploy needed):**

```sql
-- Stuck in-flight idempotency row (process died mid-request):
-- clients are locked out of this key until TTL; release it early:
DELETE FROM idempotency_records
WHERE scope = 'POST:/route:actor' AND idempotency_key = '...'
  AND status = 'in_progress' AND expires_at < now();   -- or force earlier

-- Stuck executing intent (process died between claim and receipt):
-- verify against the audit trail first, then fail it explicitly:
UPDATE approval_intents
SET status = 'failed', failure_reason = 'interrupted by process restart',
    completed_at = now()
WHERE id = '...' AND status = 'executing' AND receipt IS NULL;
```

**Rollback of this change set:**

- No schema changes: both fixes are code-only. Reverting the commits
  restores prior behavior (and, for idempotency, the raw-500 regression).
- The idempotency claim-loop and the conditional cancel/expire claims are
  backward compatible with every existing public API, status code and
  response shape — clients only ever saw 409s that were already
  documented.
- Approval-intent enforcement itself remains behind
  `MAINTAINER_APPROVAL_INTENTS_ENFORCED` (off by default): flipping the
  flag off reverts the role routes to direct execution instantly, while
  already-issued intents stay queryable and verifiable.

**Adding the harness to a new mutation:** give it a fake repository whose
write method models the real guard (conditional UPDATE, unique index),
route the operation through `runConcurrently`/`duplicateSubmissions`/
`retryStorm`, and assert with `expectSuccessCount` + `rejectionSummary`.
Keep the fake's async boundaries real — they are where races live.
