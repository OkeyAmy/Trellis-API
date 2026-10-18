/*
 * Canonical fingerprints for approval intents (#220).
 *
 * The fingerprint is the replay key of an intent: it commits to *what* will
 * be done (action, actor, resource, reason, payload) under a versioned
 * schema, over canonical JSON, so it is reproducible across processes and
 * Node versions. Deliberately excluded: the intent id (assigned on insert)
 * and the approver (chosen after the proposal exists).
 *
 * A fingerprint is not an authorization credential — it only deduplicates
 * and binds; execution re-checks the actor, role, expiry and single-use
 * state. See docs/OPERATION_RECEIPTS_AND_STATE_DRIFT.md for the same rule
 * on operation receipts.
 */

import { createHash } from "crypto";
import { canonicalJson } from "../../../common/serialization/canonical-json";
import {
  APPROVAL_INTENT_SCHEMA,
  IntentCommitment,
} from "./approval-intent.types";

export function sha256Hex(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

/**
 * The exact bytes an intent's fingerprint commits to. Exposed separately so
 * tests (and future tooling) can show *why* two fingerprints differ.
 */
export function intentCommitmentDocument(commitment: IntentCommitment): string {
  return canonicalJson({
    schema: APPROVAL_INTENT_SCHEMA,
    action: commitment.action,
    actorId: commitment.actorId,
    resourceType: commitment.resourceType,
    resourceId: commitment.resourceId,
    reason: commitment.reason,
    payload: commitment.payload,
  });
}

/** sha256 over {@link intentCommitmentDocument}; stable across runs. */
export function approvalIntentFingerprint(
  commitment: IntentCommitment,
): string {
  return sha256Hex(intentCommitmentDocument(commitment));
}

/**
 * Hash of just the payload. Stored separately so a reviewer can diff the
 * payload of two intents without recomputing their full fingerprints.
 */
export function intentPayloadHash(payload: Record<string, unknown>): string {
  return sha256Hex(canonicalJson(payload));
}
