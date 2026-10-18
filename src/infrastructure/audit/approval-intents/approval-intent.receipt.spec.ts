import { createHmac, timingSafeEqual } from "crypto";
import {
  receiptCanonicalBytes,
  receiptDocument,
  signReceipt,
  verifyReceipt,
  ReceiptSigner,
} from "./approval-intent.receipt";
import { ExportSigningService } from "../algorithms/export-signing.service";
import {
  ApprovalIntentStatus,
  ReceiptIntegrity,
  SignedIntentReceipt,
} from "./approval-intent.types";

function fakeSigner(secret = "unit-test-key"): ReceiptSigner {
  const hmac = (value: string): string =>
    createHmac("sha256", secret).update(value).digest("hex");
  return {
    sign: hmac,
    verify(payload, signature) {
      try {
        const expected = Buffer.from(hmac(payload), "hex");
        const received = Buffer.from(signature, "hex");
        return expected.length === received.length && timingSafeEqual(expected, received);
      } catch {
        return false;
      }
    },
  };
}

function executedReceipt(
  overrides: Partial<SignedIntentReceipt> = {},
): SignedIntentReceipt {
  return receiptDocument({
    intentId: "intent-1",
    fingerprint: "a".repeat(64),
    action: "user.role.assigned",
    actorId: "admin-1",
    actorRole: "ADMIN",
    approverId: null,
    resourceType: "user",
    resourceId: "user-9",
    reason: "Promote on-call operator for incident 412",
    payloadHash: "b".repeat(64),
    status: ApprovalIntentStatus.COMPLETED,
    failureReason: null,
    requestedAt: "2026-10-18T10:00:00.000Z",
    completedAt: "2026-10-18T10:00:03.000Z",
    signedAt: "2026-10-18T10:00:03.050Z",
    ...overrides,
  });
}

describe("signed approval intent receipts (#220)", () => {
  it("stamps the schema id into every receipt", () => {
    expect(executedReceipt().schema).toBe("trellis.audit.approval-intent.v1");
  });

  it("signs a receipt so it round-trips verification", () => {
    const receipt = executedReceipt();
    const signer = fakeSigner();
    const integrity = signReceipt(receipt, signer);

    expect(integrity.receiptHash).toMatch(/^[0-9a-f]{64}$/);
    expect(integrity.signature).toMatch(/^[0-9a-f]{64}$/);
    expect(integrity.signingAlgorithm).toBe("HMAC-SHA256");
    expect(verifyReceipt(receipt, integrity, signer)).toEqual({
      valid: true,
      recomputedHash: integrity.receiptHash,
      errors: [],
    });
  });

  it("canonicalizes the document so field order cannot change the hash", () => {
    const receipt = executedReceipt();
    const reordered = receiptDocument({
      signedAt: receipt.signedAt,
      completedAt: receipt.completedAt,
      requestedAt: receipt.requestedAt,
      status: receipt.status,
      failureReason: receipt.failureReason,
      payloadHash: receipt.payloadHash,
      reason: receipt.reason,
      resourceId: receipt.resourceId,
      resourceType: receipt.resourceType,
      approverId: receipt.approverId,
      actorRole: receipt.actorRole,
      actorId: receipt.actorId,
      action: receipt.action,
      fingerprint: receipt.fingerprint,
      intentId: receipt.intentId,
    });
    expect(receiptCanonicalBytes(reordered)).toBe(
      receiptCanonicalBytes(receipt),
    );
    expect(signReceipt(reordered, fakeSigner()).receiptHash).toBe(
      signReceipt(receipt, fakeSigner()).receiptHash,
    );
  });

  it("detects an edit to any recorded field", () => {
    const signer = fakeSigner();
    const integrity = signReceipt(executedReceipt(), signer);

    const tamperedFields: Array<Partial<SignedIntentReceipt>> = [
      { actorId: "admin-2" },
      { resourceId: "user-10" },
      { reason: "rewritten justification" },
      { payloadHash: "c".repeat(64) },
      { status: ApprovalIntentStatus.FAILED, failureReason: "swapped" },
      { completedAt: "2026-10-18T11:00:00.000Z" },
      { approverId: "admin-9" },
    ];
    for (const override of tamperedFields) {
      const result = verifyReceipt(
        executedReceipt(override),
        integrity,
        signer,
      );
      expect(result.valid).toBe(false);
      expect(result.errors.join(" ")).toMatch(/hash mismatch/);
    }
  });

  it("rejects a hash forged with a different signing key", () => {
    const tampered = executedReceipt({ actorId: "admin-2" });
    const attacker = fakeSigner("attacker-key");
    const forged = signReceipt(tampered, attacker);

    const result = verifyReceipt(tampered, forged, fakeSigner("real-key"));
    expect(result.valid).toBe(false);
    expect(result.errors.join(" ")).toMatch(/Invalid HMAC-SHA256 signature/);
  });

  it("reports a malformed signature instead of throwing at the reviewer", () => {
    const receipt = executedReceipt();
    const signer = fakeSigner();
    const integrity = signReceipt(receipt, signer);

    const broken: ReceiptIntegrity = {
      ...integrity,
      signature: "zz-not-hex",
    };
    const result = verifyReceipt(receipt, broken, signer);
    expect(result.valid).toBe(false);
    expect(result.errors.length).toBeGreaterThan(0);
  });

  it("flags a missing integrity block", () => {
    const result = verifyReceipt(
      executedReceipt(),
      undefined as unknown as ReceiptIntegrity,
      fakeSigner(),
    );
    expect(result.valid).toBe(false);
    expect(result.errors.join(" ")).toMatch(/integrity block is missing/);
  });

  it("only issues receipts for executed intents", () => {
    expect(() =>
      signReceipt(
        executedReceipt({ status: ApprovalIntentStatus.PROPOSED as never }),
        fakeSigner(),
      ),
    ).toThrow("only issued for executed intents");
  });

  it("verifies receipts signed by the real ExportSigningService", () => {
    const previous = process.env.AUDIT_EXPORT_SIGNING_KEY;
    process.env.AUDIT_EXPORT_SIGNING_KEY = "unit-test-signing-key";
    try {
      const service = new ExportSigningService();
      const receipt = executedReceipt();
      const integrity = signReceipt(receipt, service);

      expect(verifyReceipt(receipt, integrity, service).valid).toBe(true);
      expect(
        verifyReceipt(
          executedReceipt({ actorId: "admin-2" }),
          integrity,
          service,
        ).valid,
      ).toBe(false);
    } finally {
      if (previous === undefined) {
        delete process.env.AUDIT_EXPORT_SIGNING_KEY;
      } else {
        process.env.AUDIT_EXPORT_SIGNING_KEY = previous;
      }
    }
  });

  it("fails loudly when the signing key is not configured", () => {
    const previous = process.env.AUDIT_EXPORT_SIGNING_KEY;
    delete process.env.AUDIT_EXPORT_SIGNING_KEY;
    try {
      const service = new ExportSigningService();
      expect(() => signReceipt(executedReceipt(), service)).toThrow(
        "AUDIT_EXPORT_SIGNING_KEY is not configured",
      );
    } finally {
      if (previous !== undefined) {
        process.env.AUDIT_EXPORT_SIGNING_KEY = previous;
      }
    }
  });
});
