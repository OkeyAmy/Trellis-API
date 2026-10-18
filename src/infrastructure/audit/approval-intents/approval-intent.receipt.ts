/*
 * Receipt construction and verification for approval intents (#220).
 *
 * A receipt is the signed, reviewable record of one *executed* intent. The
 * document is canonicalized (sorted keys, no whitespace) before hashing, the
 * hash is signed with the audit signing key (HMAC-SHA256), and both the hash
 * and the signature are stored next to the intent.
 *
 * Verification is deliberately two-layered:
 *   1. recompute the hash from the stored document — detects any edit to the
 *      recorded action, actor, reason, outcome or timestamps;
 *   2. verify the signature over that hash — detects a forged hash.
 *
 * The signer is injected as a plain structural interface so tests can pass a
 * deterministic fake; production wires the existing `ExportSigningService`,
 * the same helper that signs evidence bundles.
 */

import { canonicalJson } from "../../../common/serialization/canonical-json";
import {
  APPROVAL_INTENT_SCHEMA,
  APPROVAL_INTENT_SIGNATURE_ALGORITHM,
  ApprovalIntentStatus,
  ReceiptIntegrity,
  SignedIntentReceipt,
} from "./approval-intent.types";
import { sha256Hex } from "./approval-intent.fingerprint";

/** Structural subset of `ExportSigningService` used to sign receipts. */
export interface ReceiptSigner {
  sign(payload: string): string;
  verify(payload: string, signature: string): boolean;
}

/** Fields a caller supplies; the schema id is stamped on top. */
export type ReceiptDocumentInput = Omit<SignedIntentReceipt, "schema">;

/** Stamp the schema id so receipt format changes stay distinguishable. */
export function receiptDocument(input: ReceiptDocumentInput): SignedIntentReceipt {
  return { schema: APPROVAL_INTENT_SCHEMA, ...input };
}

/** Canonical bytes a receipt commits to. Exposed for tests and tooling. */
export function receiptCanonicalBytes(receipt: SignedIntentReceipt): string {
  return canonicalJson(receipt);
}

export function hashReceipt(receipt: SignedIntentReceipt): string {
  return sha256Hex(receiptCanonicalBytes(receipt));
}

/** Produce the integrity block persisted with a terminal receipt. */
export function signReceipt(
  receipt: SignedIntentReceipt,
  signer: ReceiptSigner,
): ReceiptIntegrity {
  if (
    receipt.status !== ApprovalIntentStatus.COMPLETED &&
    receipt.status !== ApprovalIntentStatus.FAILED
  ) {
    throw new Error(
      `Receipts are only issued for executed intents, not ${receipt.status}`,
    );
  }
  const receiptHash = hashReceipt(receipt);
  return {
    receiptHash,
    signature: signer.sign(receiptHash),
    signingAlgorithm: APPROVAL_INTENT_SIGNATURE_ALGORITHM,
  };
}

export interface ReceiptVerification {
  valid: boolean;
  recomputedHash: string;
  errors: string[];
}

/**
 * Recompute + verify. Never throws: a malformed signature is reported as an
 * error so a reviewer sees *why* a receipt fails verification instead of a
 * generic 500.
 */
export function verifyReceipt(
  receipt: SignedIntentReceipt,
  integrity: ReceiptIntegrity,
  signer: ReceiptSigner,
): ReceiptVerification {
  const errors: string[] = [];

  const recomputedHash = hashReceipt(receipt);

  if (receipt.schema !== APPROVAL_INTENT_SCHEMA) {
    errors.push(
      `Unknown receipt schema "${receipt.schema}"; expected "${APPROVAL_INTENT_SCHEMA}"`,
    );
  }
  if (!integrity || typeof integrity.receiptHash !== "string") {
    errors.push("Receipt integrity block is missing");
    return { valid: false, recomputedHash, errors };
  }
  if (integrity.receiptHash !== recomputedHash) {
    errors.push(
      `Receipt hash mismatch: recorded ${integrity.receiptHash}, recomputed ${recomputedHash}`,
    );
  }
  if (integrity.signingAlgorithm !== APPROVAL_INTENT_SIGNATURE_ALGORITHM) {
    errors.push(
      `Unexpected signing algorithm "${integrity.signingAlgorithm}"`,
    );
  }

  let signatureValid = false;
  try {
    signatureValid = signer.verify(recomputedHash, integrity.signature);
  } catch (error) {
    errors.push(
      `Signature verification error: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  if (!signatureValid && !errors.some((e) => e.startsWith("Signature"))) {
    errors.push("Invalid HMAC-SHA256 signature over the receipt hash");
  }

  return { valid: errors.length === 0, recomputedHash, errors };
}
