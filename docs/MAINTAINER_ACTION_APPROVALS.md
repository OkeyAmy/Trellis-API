# Maintainer Action Approvals (#220)

Signed, single-use approval intents for high-impact maintainer actions. An
intent is a durable statement — *who* will do *what* to *which resource*, and
*why* — fingerprinted over canonical JSON, signed at rest with HMAC-SHA256,
and consumed exactly once by the route it authorizes, which stores a signed
receipt when it finishes.

## Enabling

The flow is **off by default**; with the flag unset, every route behaves
byte-identically to the pre-approval API.

```bash
MAINTAINER_APPROVAL_INTENTS_ENFORCED=true
```

Accepted truthy values: `true`, `1`, `yes` (case-insensitive). The flag is
read at request time, not at boot, so a redeploy is not required to flip it.

## Flow

```
POST /admin/intents              PATCH /admin/users/:id/role
  (propose, signed)     ------>    with approvalIntentId
        |                                  |
     proposed  --execute claim-->     executing
        |                                  |
   cancel / expire                completed | failed
     (terminal)                    (signed receipt)
```

1. **Propose** — `POST /admin/intents` with a catalogued `action`
   (e.g. `access.role.assigned`), `resourceType`/`resourceId`, a mandatory
   `reason`, and the exact `payload` the execution will use
   (`{"role": "MAINTAINER"}` for a role grant). Optionally designate an
   `approverId` (second pair of eyes, must differ from the proposer) and a
   `ttlSeconds` (60…604800, default 900).
2. **Execute** — the authorized route consumes the intent:
   `PATCH /admin/users/:id/role` takes `approvalIntentId` in the body,
   `DELETE /admin/users/:id/role` takes it as `?approvalIntentId=`.
   The route refuses an intent that commits to a different action, user or
   role (409), and the service re-checks expiry, executor authorization and
   single-use state before running the change.
3. **Review** — `GET /admin/intents/:id` for the row,
   `GET /admin/intents/:id/receipt/verify` re-runs receipt verification
   (re-canonicalizes the stored document, recomputes the hash, checks the
   HMAC).

With enforcement on and no intent supplied, the role routes answer
**428 Precondition Required** and explain what to propose.

## Guarantees and edge cases

| Situation | Behaviour |
| --- | --- |
| Identical intent already proposed | 409; the conflict message names the existing intent id |
| Execution after TTL | Intent is transitioned to `expired`, request fails 409 — it can never execute late |
| Two executions race | Atomic conditional update (`proposed → executing`); exactly one wins, the loser gets 409 |
| Operation throws | A signed **failure** receipt is stored (with the error message), then the original error is rethrown |
| Intent already terminal | 409; terminal states are final, nothing is resurrected |
| Approver designated | Only `approverId` may execute; anyone else gets 403 |
| No approver | Executor must hold `ADMIN` or `MAINTAINER` (re-checked server-side) |
| Self-approval | Rejected at propose time (400) |
| Payload not canonicalizable (`undefined`, functions, circular refs) | Propose fails loudly instead of signing a lossy form |
| Receipt document edited after the fact | `verify` reports a hash mismatch (the integrity block still holds the original) |
| Forged receipt hash | Signature check over the recomputed hash fails |
| Cancellation | Only from `proposed`; the *proposal's* reason is part of the signed commitment and is never overwritten — the cancellation reason travels in the evidence event, recorded under the canceller |

## Failure modes

- **Proposal evidence cannot be written** (audit chain outage): fail closed —
  the intent is cancelled and the caller gets 503. Nothing stays executable
  that cannot be evidenced.
- **Execution evidence append fails**: the receipt is already durable in the
  intent row; the surrounding audit event is best-effort and only its index
  into the trail is lost (logged as an error).
- **Signing key missing** (`AUDIT_EXPORT_SIGNING_KEY` unset): signing fails
  at propose/execute time with a clear error — nothing is signed silently.
- **Cancel evidence fails**: the intent stays cancelled (the safe direction)
  and the failure is logged.

## Operational notes

- Bulk cleanup: `ApprovalIntentService.expireDueIntents()` ages out every
  due `proposed` row; rows carry the indexes for execution, expiry, actor and
  action queries.
- The migration set is idempotent (`IF NOT EXISTS`), so re-running it on an
  existing database is safe.

## Rollback

- **Flag off** (or unset): routes revert to direct execution immediately;
  existing intents stay queryable and verifiable but nothing consumes them.
- **Code rollback**: revert the feature commit(s). The `approval_intents`
  table is additive; `down` migrations drop only their own column/table and
  touch nothing else. Signed receipts already issued remain readable with
  the same key.
- No public response shapes changed: the role routes return the same
  `{id, role}` body as before.

## Tests

Colocated specs cover the transition table, fingerprint determinism and
binding, receipt tamper/forgery detection, propose validation and dedupe,
fail-closed evidence, atomic claim races, expiry paths, executor
authorization, the stored-receipt verification path, the REST wiring, and
the flag-off/flag-on behaviour of both role routes
(`approval-intent.*.spec.ts`, `admin-role.controller.spec.ts`,
`src/migrations/1792339200000*` and `1792342800000*`).
