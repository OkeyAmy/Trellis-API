/*
 * State machine and shared types for maintainer approval intents (#220).
 *
 * A high-impact maintainer action is split into two steps:
 *
 *   1. the *intent* — what will be done, by whom, to which resource, why —
 *      persisted and fingerprinted over canonical JSON, and signed at rest;
 *   2. the *execution* — consumes the intent exactly once and ends in a
 *      signed receipt that can be reviewed after completion or failure.
 *
 * The schema id below is embedded in every fingerprint and every receipt
 * document, so a future format change cannot be confused with historical
 * records: old receipts keep verifying against their original schema.
 */

/** Format id stamped into fingerprints and receipt documents. */
export const APPROVAL_INTENT_SCHEMA = "trellis.audit.approval-intent.v1";

/** Signature algorithm recorded alongside every receipt. */
export const APPROVAL_INTENT_SIGNATURE_ALGORITHM = "HMAC-SHA256";

export enum ApprovalIntentStatus {
  /** Persisted and signed; waiting for an actor to execute it. */
  PROPOSED = "proposed",
  /** Claimed by an execution; no other execution may start. */
  EXECUTING = "executing",
  /** The underlying action succeeded and a receipt was signed. */
  COMPLETED = "completed",
  /** The underlying action failed (or was reverted); a signed failure receipt exists. */
  FAILED = "failed",
  /** The intent aged out before execution; it can never execute. */
  EXPIRED = "expired",
  /** Withdrawn by a maintainer before execution. */
  CANCELLED = "cancelled",
}

/**
 * Legal status transitions. Anything else is a bug or an attempt to rewrite
 * history: terminal states are terminal, and a receipt is only ever produced
 * by `executing -> completed | failed`.
 */
const ALLOWED_TRANSITIONS: Record<ApprovalIntentStatus, ApprovalIntentStatus[]> = {
  [ApprovalIntentStatus.PROPOSED]: [
    ApprovalIntentStatus.EXECUTING,
    ApprovalIntentStatus.EXPIRED,
    ApprovalIntentStatus.CANCELLED,
  ],
  [ApprovalIntentStatus.EXECUTING]: [
    ApprovalIntentStatus.COMPLETED,
    ApprovalIntentStatus.FAILED,
  ],
  [ApprovalIntentStatus.COMPLETED]: [],
  [ApprovalIntentStatus.FAILED]: [],
  [ApprovalIntentStatus.EXPIRED]: [],
  [ApprovalIntentStatus.CANCELLED]: [],
};

/** Statuses that can never change again. */
export const TERMINAL_INTENT_STATUSES: readonly ApprovalIntentStatus[] = [
  ApprovalIntentStatus.COMPLETED,
  ApprovalIntentStatus.FAILED,
  ApprovalIntentStatus.EXPIRED,
  ApprovalIntentStatus.CANCELLED,
];

export function isTerminalIntentStatus(status: ApprovalIntentStatus): boolean {
  return TERMINAL_INTENT_STATUSES.includes(status);
}

/**
 * Returns `next` if the transition is legal, otherwise throws.
 *
 * The returned value carries no timestamps: callers persist their own
 * `startedAt`/`completedAt` so that a retry after a failed save cannot move
 * a recorded timestamp twice.
 */
export function transitionIntentStatus(
  current: ApprovalIntentStatus,
  next: ApprovalIntentStatus,
): ApprovalIntentStatus {
  if (current === next) return next;
  const allowed = ALLOWED_TRANSITIONS[current];
  if (!allowed || !allowed.includes(next)) {
    throw new Error(
      `Invalid approval intent transition: ${current} -> ${next}`,
    );
  }
  return next;
}

/** Who is proposing/executing the intent. */
export interface ApprovalIntentActor {
  id: string;
  role?: string | null;
  /** Maps to `SensitiveActionEvent.actorType`; defaults to `maintainer`. */
  type?: string | null;
  ipAddress?: string | null;
  userAgent?: string | null;
}

/** Everything that identifies *what* an intent will do. */
export interface IntentCommitment {
  action: string;
  actorId: string;
  resourceType: string;
  resourceId: string;
  reason: string;
  payload: Record<string, unknown>;
}

/** The persisted, signed statement that a maintainer intends an action. */
export interface ApprovalIntentRequest extends IntentCommitment {
  actor: ApprovalIntentActor;
  /** Optional second pair of eyes; enforced per action by the service. */
  approverId?: string | null;
  /** Non-secret context (request id, ticket, operation name). */
  metadata?: Record<string, unknown>;
  /** Lifetime of the intent in seconds; defaults to a service-level value. */
  ttlSeconds?: number;
}

/**
 * The signed receipt document produced when an execution reaches a terminal
 * state. Canonicalized (sorted keys, no whitespace) before hashing, so the
 * same intent always yields byte-identical receipt bytes.
 */
export interface SignedIntentReceipt {
  schema: string;
  intentId: string;
  fingerprint: string;
  action: string;
  actorId: string;
  actorRole: string | null;
  approverId: string | null;
  resourceType: string;
  resourceId: string;
  reason: string;
  payloadHash: string;
  /** Always `completed` or `failed` — receipts exist only for executions. */
  status: ApprovalIntentStatus.COMPLETED | ApprovalIntentStatus.FAILED;
  failureReason: string | null;
  /** ISO-8601 timestamps, second-level precision is not assumed. */
  requestedAt: string;
  completedAt: string;
  signedAt: string;
}

/** Integrity block stored next to a receipt. */
export interface ReceiptIntegrity {
  receiptHash: string;
  signature: string;
  signingAlgorithm: string;
}
